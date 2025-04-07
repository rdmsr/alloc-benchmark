#include "fayt/slab.h"
#include <iomanip>
#include <vector>
#undef CPU_COUNT
#define CPU_COUNT 16
#include "kmem/slab.h"
#undef CPU_COUNT
#include <frg/slab.hpp>
#include <frg/spinlock.hpp>
#include <iostream>
#include <liballoc.h>
#include <mimalloc.h>
#include <new>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <thread>

#define BARRIER(PTR) asm volatile("" : : "r"(PTR) : "memory")

extern "C" int print(const char *str, ...) {
  va_list args;
  va_start(args, str);
  vprintf(str, args);
  va_end(args);

  return 0;
}

void *spalloc(void *a, size_t size) {
  (void)a;
  return mmap(NULL, size * 4096, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void spfree(void *ptr, uint64_t, uint64_t) {}

struct VirtualAllocator {
public:
  uintptr_t map(size_t length) {
    return (uintptr_t)mmap(nullptr, length, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  }

  void unmap(uintptr_t address, size_t length) {
    munmap((void *)address, length);
  }
};

struct FaytLock {

  void lock() { spinlock(&lock_); }

  void unlock() { spinrelease(&lock_); }

  struct spinlock lock_;
};

struct RandomGenerator {
  uint32_t state[4];
  uint32_t advance() {
    uint32_t t = state[3];

    uint32_t s = state[0];
    state[3] = state[2];
    state[2] = state[1];
    state[1] = s;

    t ^= t << 11;
    t ^= t >> 8;
    return state[0] = t ^ s ^ (s >> 19);
  }
  RandomGenerator() { arc4random_buf(state, sizeof(state)); }
};
thread_local RandomGenerator thread_rng{};

static auto alloc = VirtualAllocator{};
static auto pool = frg::slab_pool<VirtualAllocator, FaytLock>{alloc};
static auto slab = frg::slab_allocator<VirtualAllocator, FaytLock>{&pool};

constexpr int NUM_ALLOCS = 10'000'000;

static int num_threads = 1;

static void frg_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = slab.allocate(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      slab.free(pool[--idx]);
    }
  }
}

static void kmem_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = kmem_malloc(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      kmem_free(pool[--idx]);
    }
  }
}

static void mimalloc_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = mi_malloc(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      mi_free(pool[--idx]);
    }
  }
}

static void malloc_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = malloc(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      free(pool[--idx]);
    }
  }
}

static struct slab_pool fayt_pool = {
    .page_size = 4096, .page_alloc = spalloc, .page_free = spfree};

static void fayt_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = fayt_alloc(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      fayt_free(pool[--idx]);
    }
  }
}

static struct spinlock lock;

extern "C" {
int liballoc_lock() {
  spinlock(&lock);
  return 0;
}

int liballoc_unlock() {
  spinrelease(&lock);
  return 0;
}

void *liballoc_alloc(size_t pages) { return spalloc(nullptr, pages); }

int liballoc_free(void *ptr, size_t pages) { return munmap(ptr, pages * 4096); }
}

static void liballoc_bench() {
  for (int i = 0; i < (NUM_ALLOCS / num_threads) / 0x1000; i++) {
    void *pool[0x1000];
    int idx = 0;

    for (int i = 0; i < 0x1000; i++) {
      pool[idx] = kmalloc(thread_rng.advance() % 256);
      BARRIER(pool[idx]);
      idx++;
    }

    for (int i = 0; i < 0x1000; i++) {
      kfree(pool[--idx]);
    }
  }
}

static void run_bench(const char *name, void (*bench)(), int num_threads) {
  std::vector<std::thread> threads(num_threads);

  auto time = std::chrono::high_resolution_clock::now();

  for (int i = 0; i < num_threads; i++) {
    threads[i] = std::thread(bench);

    // Create a cpu_set_t object representing a set of CPUs. Clear it and mark
    // only CPU i as set.
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(i, &cpuset);
    int rc = pthread_setaffinity_np(threads[i].native_handle(),
                                    sizeof(cpu_set_t), &cpuset);

    if (rc != 0) {
      std::cerr << "Error calling pthread_setaffinity_np: " << rc << std::endl;
    }
  }

  for (int i = 0; i < num_threads; i++) {
    threads[i].join();
  }

  auto end = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> diff = end - time;

  std::cout << "- " << std::left << std::setw(10) << name << ": "
            << diff.count() << "s" << std::endl;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s <threads>\n", argv[0]);
    return 1;
  }

  num_threads = atoi(argv[1]);

  if (num_threads < 1) {
    printf("Invalid number of threads\n");
    return 1;
  }

  int cpu_count = std::thread::hardware_concurrency();

  if (num_threads > cpu_count) {
    printf("Number of threads (%d) exceeds CPU count (%d)\n", num_threads,
           cpu_count);
    return 1;
  }

  kmem_init();
  slab_cache_create(&fayt_pool, "CACHE32", 32);
  slab_cache_create(&fayt_pool, "CACHE64", 64);
  slab_cache_create(&fayt_pool, "CACHE128", 128);
  slab_cache_create(&fayt_pool, "CACHE256", 256);
  slab_cache_create(&fayt_pool, "CACHE512", 512);
  slab_cache_create(&fayt_pool, "CACHE1024", 1024);

  std::cout << NUM_ALLOCS << " allocations over " << num_threads
            << " threads: " << std::endl;
  run_bench("kmem", kmem_bench, num_threads);
  run_bench("frigg", frg_bench, num_threads);
  run_bench("mimalloc", mimalloc_bench, num_threads);
  run_bench("libc", malloc_bench, num_threads);
  run_bench("fayt", fayt_bench, num_threads);
  run_bench("liballoc", liballoc_bench, num_threads);

  return 0;
}
