from bcc import BPF
import ctypes as ct
import sys
import argparse
import os

# 解析命令行参数
parser = argparse.ArgumentParser(description="Trace process load time with a specified name.")
parser.add_argument("process_name", help="The name of the target process to trace")
args = parser.parse_args()
target_process_name = args.process_name

# 定义事件结构体（与 eBPF 中一致）
class Event(ct.Structure):
    _fields_ = [
        ("comm", ct.c_char * 16),
        ("pid", ct.c_uint32),
        ("delta", ct.c_ulonglong)
    ]

# 定义 eBPF 程序
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/time.h>

// 定义事件结构体
struct event_t {
    char comm[16];
    u32 pid;
    u64 delta;
};

// 定义哈希表存储进程的启动时间和PID
BPF_HASH(start_time_map, u32, u64);
BPF_RINGBUF_OUTPUT(events, 1 << 10); // 1024 pages

// 监控 execve 系统调用进入事件
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start_time_map.update(&pid, &ts);
    return 0;
}

// 监控 execve 系统调用退出事件
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts = start_time_map.lookup(&pid);

    if (start_ts) {
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        u64 delta = bpf_ktime_get_ns() - *start_ts;

        struct event_t event = {0};
        __builtin_memcpy(event.comm, comm, sizeof(event.comm));
        event.pid = pid;
        event.delta = delta / 1000;
        events.ringbuf_output(&event, sizeof(event), 0);
        start_time_map.delete(&pid);
    }
    return 0;
}
"""

# 初始化 BPF 模块
b = BPF(text=bpf_text)

exit_flag = False

# 设置 perf buffer 来监听事件
def print_event(cpu, data, size):
    global exit_flag
    event = ct.cast(data, ct.POINTER(Event)).contents
    comm = event.comm.decode('utf-8', 'replace')
    if comm == target_process_name:
        print(f"Process Name: {event.comm.decode('utf-8', 'replace')} PID: {event.pid} Load Time: {event.delta} us")
        with open("load_data.txt", "a") as output_file:
            output_file.write(f"{event.delta} \n")
        exit_flag = True

# 创建 ring buffer 并开始监听
b["events"].open_ring_buffer(print_event)

with open("execve_start.txt", "w") as output_file:
    output_file.write(f"ready")

try:
    while not exit_flag:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    pass