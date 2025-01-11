from bcc import BPF
import ctypes
import argparse

parser = argparse.ArgumentParser(description="Trace process execution with a specified name.")
parser.add_argument("process_name", help="The name of the target process to trace")
args = parser.parse_args()

target_process_name = args.process_name
tracked_pids = set()
exit_flag = False

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/sched.h>

struct exec_event {
    u32 pid;
    char comm[16];
};

struct exit_event {
    u32 pid;
    u64 total_bytes;
    u64 total_io_time_ns;
};

struct ipv4_key_t {
    u32 pid;
};

struct disk_io_event {
    u64 total_io_time_ns;
    u64 last_io_start;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(exit_events);
BPF_HASH(total_bytes, struct ipv4_key_t);
BPF_HASH(io_events, u32, struct disk_io_event);
BPF_HASH(target_pids, u32);

// 捕获进程启动，发送名称和 PID 到用户空间，并初始化 I/O 时间记录
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    struct exec_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    exec_events.perf_submit(args, &event, sizeof(event));

    return 0;
}

// 探测内核中的 tcp_sendmsg 函数
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!io_events.lookup(&pid))
        return 0;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t key = {.pid = pid};
        total_bytes.increment(key, size);
    }
    return 0;
}

// 探测内核中的 tcp_cleanup_rbuf 函数
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!io_events.lookup(&pid) || copied <= 0)
        return 0;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t key = {.pid = pid};
        total_bytes.increment(key, copied);
    }
    return 0;
}

// 记录 I/O 开始时间
TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct disk_io_event *io = io_events.lookup(&pid);

    if (io) {
        io->last_io_start = bpf_ktime_get_ns();
    }
    return 0;
}

// 记录 I/O 结束时间并累计耗时
TRACEPOINT_PROBE(block, block_rq_complete) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct disk_io_event *io = io_events.lookup(&pid);

    if (io && io->last_io_start > 0) {
        u64 io_end = bpf_ktime_get_ns();
        io->total_io_time_ns += io_end - io->last_io_start;
        io->last_io_start = 0;
    }
    return 0;
}

// 捕获进程退出，输出结果并清理状态
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!target_pids.lookup(&pid))
        return 0;

    struct disk_io_event *io = io_events.lookup(&pid);
    struct ipv4_key_t key = {.pid = pid};
    u64 *bytes = total_bytes.lookup(&key);

    struct exit_event event = {};
    event.pid = pid;
    if (bytes) {
        event.total_bytes = *bytes;
        total_bytes.delete(&key);
    } else {
        event.total_bytes = 0;
    }

    if (io) {
        event.total_io_time_ns = io->total_io_time_ns;
        io_events.delete(&pid);
    }

    exit_events.perf_submit(args, &event, sizeof(event));

    return 0;
}
"""

b = BPF(text=bpf_program)

# 定义事件结构体（与 eBPF 中一致）
class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16)
    ]

class ExitEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("total_bytes", ctypes.c_ulonglong),
        ("total_io_time_ns", ctypes.c_ulonglong)
    ]

class IoEvent(ctypes.Structure):
    _fields_ = [
        ("total_io_time_ns", ctypes.c_ulonglong),
        ("last_io_start", ctypes.c_ulonglong)
    ]

# 绑定 perf event 输出
def handle_exec_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
    pid = event.pid
    comm = event.comm.decode("utf-8")

    if comm == target_process_name:
        print(f"Matched target process: {comm} with PID {pid}, Tracking network traffic and I/O time for target process...")
        tracked_pids.add(pid)
        io_event = IoEvent(total_io_time_ns=0, last_io_start=0)
        b['io_events'][ctypes.c_uint32(pid)] = io_event
        b['target_pids'][ctypes.c_uint32(pid)] = ctypes.c_int(1)

def handle_exit_event(cpu, data, size):
    global exit_flag
    event = ctypes.cast(data, ctypes.POINTER(ExitEvent)).contents
    pid = event.pid
    total_bytes_kb = int(event.total_bytes / 1024)
    total_io_time_ms = event.total_io_time_ns / 1000000

    if pid in tracked_pids:
        print(f"Process exited: PID {pid}, Total Network Traffic: {total_bytes_kb} KB, Total IO Time: {total_io_time_ms:.2f} ms")
        with open("net_flow.txt", "w") as output_file:
            output_file.write(f"{total_bytes_kb} \n")
        with open("load_data.txt", "w") as output_file:
            output_file.write(f"{total_io_time_ms:.2f} \n")
        tracked_pids.remove(pid)
        del b['target_pids'][ctypes.c_uint32(pid)]
        exit_flag = True

# 绑定事件
b["exec_events"].open_perf_buffer(handle_exec_event)
b["exit_events"].open_perf_buffer(handle_exit_event)
print("start Tracking network traffic and I/O time for target program.")

with open("tmp_start.txt", "w") as output_file:
    output_file.write(f"ready")

while not exit_flag:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()