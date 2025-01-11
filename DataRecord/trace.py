
from bcc import BPF
import sys
import time
import signal
import argparse
import os
import subprocess

# 解析命令行参数
parser = argparse.ArgumentParser(description="Trace process execution with a specified name.")
parser.add_argument("process_name", help="The name of the target process to trace")
parser.add_argument("--stat", action="store_true", help="Execute stat function for the target process")
parser.add_argument("--monitor", action="store_true", help="Monitor the target process with given interval")
parser.add_argument("--mem", action="store_true", help="Monitor the memory used by process with given sample")
parser.add_argument("--interval", type=int, default=1, help="Interval in seconds for monitoring (default: 5)")
parser.add_argument("--f", type=int, default=20, help="frequence for monitoring RSS(default: 20)")
args = parser.parse_args()

target_process_name = args.process_name

# 定义 eBPF 程序
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义 Perf Buffer 的数据结构
struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

// 捕获 execve 系统调用后的事件
int trace_exec(struct tracepoint__sched__sched_process_exec *ctx) {
    struct event_t event = {};

    // 获取当前进程的 PID 和名字
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 将数据发送到用户态
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# 加载 eBPF 程序
bpf = BPF(text=bpf_text)

# 将 eBPF 程序附加到 tracepoint
tracepoint = "sched:sched_process_exec"
bpf.attach_tracepoint(tp=tracepoint, fn_name="trace_exec")

exit_flag = False

# 定义用户态处理函数
def print_event(cpu, data, size):
    global exit_flag
    event = bpf["events"].event(data)
    comm_str = event.comm.decode("utf-8", "replace").rstrip("\0")
    
    # 如果匹配到目标进程名，执行后续操作
    if comm_str == target_process_name:
        print(f"trace.py: Target process '{target_process_name}' detected with PID {event.pid}. Proceeding...")
        # 在这里添加你希望的后续操作
        bpf.detach_tracepoint(tp=tracepoint)  # 卸载 eBPF 程序
        if args.stat:
            execute_stat(event.pid)
        if args.monitor:
            monitor_process(event.pid, args.interval)
        if args.mem:
            get_memory_use(event.pid, args.f)
        exit_flag = True

# 设置 Perf Buffer 回调函数
bpf["events"].open_perf_buffer(print_event)

def execute_stat(pid):
    perf_stat_events = "instructions,cycles,task-clock,cache-references,cache-misses"
    output_file = "perf_stat.txt"

    try:
        perf_stat_proc = subprocess.Popen(
            ['perf', 'stat', '-e', perf_stat_events, '-p', str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"perf stat attached to PID: {pid}")

        # 等待子进程完成并获取输出
        stdout, stderr = perf_stat_proc.communicate()
        
        # 过滤掉包含 'seconds time elapsed' 的行
        filtered_output = []
        for line in stderr.splitlines():  # 处理 stderr，因为 perf 的统计信息通常输出到 stderr
            if "seconds time elapsed" not in line:
                filtered_output.append(line)

        # 将过滤后的输出追加到文件中
        with open(output_file, 'a') as stat_output_file:
            stat_output_file.write('\n'.join(filtered_output) + '\n')

        perf_stat_proc.wait()

    except Exception as e:
        print(f"An error occurred: {e}")

def monitor_process(pid, interval):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    read_path = os.path.join(current_dir, "read")
    read_command = [read_path, str(pid), str(interval)]
    subprocess.Popen(read_command)

def get_memory_use(pid, sample_hz=10, mem_sample_file_path="mem_sample.txt"):
    def read_process_status_vm_rss(pid):
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return line.split()[1]  
        except FileNotFoundError:
            return None  
        
    with open(mem_sample_file_path, "w") as mem_sample_file:
        print(f"Monitoring memory usage at {sample_hz} Hz. Writing results to {mem_sample_file_path}.")

        try:
            while True:
                rss = read_process_status_vm_rss(pid)
                if rss is None:  
                    break
                mem_sample_file.write(f"{rss}\n")
                mem_sample_file.flush() 
                time.sleep(1.0 / sample_hz)
        except KeyboardInterrupt:
            print("Memory monitoring interrupted by user.")
        except Exception as e:
            print(f"Error during memory monitoring: {e}")
        finally:
            mem_sample_file.close()

def signal_handler(sig, frame):
    global exit_flag
    print("\nTerminating...")
    exit_flag = True

signal.signal(signal.SIGINT, signal_handler)

# 等待并处理事件
try:
    while not exit_flag:
        bpf.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass