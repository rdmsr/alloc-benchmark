import matplotlib.pyplot as plt
import subprocess


points = {}

def run_bench(num_threads):
    print(f"* Running benchmark with {num_threads} threads")
    output = subprocess.run(["./build/bench", str(num_threads)], check=True, capture_output=True, text=True)
    output = output.stdout.splitlines()[1:]
    points[num_threads] = {}
    
    for line in output:
        comps = line.split(':')
        benchname = comps[0].strip('- ').strip()
        time = float(comps[1].strip().strip('s'))
        points[num_threads][benchname] = time


def plot():
    # Plot the data
        fig, ax = plt.subplots()
        for benchname in points[1].keys():
                x = []
                y = []
                for num_threads in points.keys():
                        x.append(num_threads)
                        y.append(points[num_threads][benchname])

                ax.plot(x, y, label=benchname)
                ax.set_xlabel('Number of Threads')
                ax.set_ylabel('Time (s)')
                ax.set_title('Benchmark Results')
                ax.legend()
                plt.savefig('bench.png')
                


for i in range(16):
    run_bench(i+1)

plot()


