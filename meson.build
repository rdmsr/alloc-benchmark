project('alloc-bench', ['c', 'cpp'], default_options: ['buildtype=release', 'b_sanitize=none', 'cpp_std=c++20'])


executable('bench', c_args: ['-ggdb'], sources: [files('main.cpp', 'kmem/slab.c', 'fayt/hash.c', 'fayt/slab.c', 'fayt/stream.c', 'liballoc.c')], include_directories: include_directories('.'),
          dependencies: [dependency('mimalloc'), dependency('frigg', fallback: ['frigg', 'frigg_dep'])])
