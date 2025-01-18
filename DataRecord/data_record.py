import subprocess
import argparse
import time
import os
import json
import re
import signal
import shlex
from collections import defaultdict


def check_bcc_library():
    try:
        import bcc
        return True
    except ImportError:
        return False
    
def check_nsys_installed():
    try:
        subprocess.run(["nsys", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False
    except subprocess.CalledProcessError:
        return False

def first_record(program_path, program_args=None):
    executable_path = os.path.abspath(program_path)
    program_name = os.path.basename(executable_path)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    trace_path = os.path.join(current_dir, "trace.py")
    execve_path = os.path.join(current_dir, "trace_iof.py")

    trace_process = subprocess.Popen(['python3', trace_path, program_name, "--mem", "--monitor"])
    execve_process = subprocess.Popen(['python3', execve_path, program_name])
    print("------------ ready for first time recording, first stat, memory use, active pages, I\O time and net flow --------------")
    while not os.path.exists("tmp_start.txt"):
        time.sleep(0.1)

    try:
        perf_stat_command_1 = ["perf", "stat", "-e", "page-faults,branches,branch-misses,task-clock", executable_path]
        if program_args:
            perf_stat_command_1.extend(shlex.split(program_args))
        with open("perf_stat.txt", "w") as output_file:  
            subprocess.run(perf_stat_command_1, check=True, stdout=output_file, stderr=output_file)

    except Exception as e:
        print(f"An error occurred: {e}")

def second_record(program_path, program_args=None):
    executable_path = os.path.abspath(program_path)
    program_name = os.path.basename(executable_path)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    trace_path = os.path.join(current_dir, "trace.py")
    execve_path = os.path.join(current_dir, "time_execve.py")

    trace_process = subprocess.Popen(['python3', trace_path, program_name, "--stat"])
    execve_process = subprocess.Popen(['python3', execve_path, program_name])
    print("------------ ready for second time recording, second stat, cpu-cycles and execve time----------------------------------")
    while not os.path.exists("execve_start.txt"):
        time.sleep(0.1)

    try:
        perf_record_command = ["perf", "record", "-e", "cpu-cycles", program_path]
        if program_args:
            perf_record_command.extend(shlex.split(program_args))
        subprocess.run(perf_record_command, check=True)

    except Exception as e:
        print(f"An error occurred: {e}")

    perf_script_command = ["sudo", "perf", "script"]
    with open("perf_script.txt", "w") as output_file:
        subprocess.run(perf_script_command, check=True, stdout=output_file)

def run_perf_commands(executable_path):
    perf_record_command = ["perf", "record", "-e", "cpu-cycles", executable_path]
    
    print(f"Executing: {' '.join(perf_record_command)}")
    subprocess.run(perf_record_command, check=True)

    perf_script_command = ["perf", "script"]
    print(f"Executing: {' '.join(perf_script_command)}")
    with open("perf_script.txt", "w") as output_file:
        subprocess.run(perf_script_command, check=True, stdout=output_file)

def run_perf_stat_commands(executable_path):
    perf_stat_command_1 = ["perf", "stat", "-e", "cache-references,cache-misses,branches,branch-misses,task-clock", executable_path]
    print(f"Executing: {' '.join(perf_stat_command_1)}")
    with open("perf_stat.txt", "w") as output_file:  
        subprocess.run(perf_stat_command_1, check=True, stdout=output_file, stderr=output_file)

    event_results = {}
    events_2 = ["instructions", "cycles", "task-clock", "page-faults"]
    perf_stat_command_2 = ["perf", "stat", "-e", "instructions,cycles,task-clock,page-faults", executable_path]
    print(f"Executing: {' '.join(perf_stat_command_2)}")
    result_2 = subprocess.run(perf_stat_command_2, check=True, text=True, capture_output=True)
    output_2 = result_2.stderr.splitlines()
    # Parse the output of the second command
    for line in output_2:
        for event in events_2:
            if event in line:
                event_results[event] = line

    # Write the combined results to a new output file
    with open("perf_stat.txt", "a") as output_file:
        for event, output_line in event_results.items():
            output_file.write(output_line + "\n")
    #with open("perf_stat.txt", "a") as output_file:  
    #    subprocess.run(perf_stat_command_2, check=True, stdout=output_file, stderr=output_file)

def monitor_process(executable_path, interval):
    process = subprocess.Popen([executable_path])
    pid = process.pid
    current_dir = os.path.dirname(os.path.abspath(__file__))
    read_path = os.path.join(current_dir, "read")
    read_command = [read_path, str(pid), str(interval)] 
    print(f"Executing: {' '.join(read_command)}")
    subprocess.run(read_command, check=True)

def run_flow_pid_script(executable_path):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    flow_path = os.path.join(current_dir, "flow_pid.py")
    process = subprocess.Popen([executable_path])
    pid = process.pid
    print(f"Started process with PID: {pid}")
    flow_pid_command = ["python3", flow_path, "-p", str(pid)]
    print(f"Executing: {' '.join(flow_pid_command)}")
    subprocess.run(flow_pid_command, check=True)

def run_nsys_profile_and_stats():
    profile_command = ["nsys", "profile", "-o", "nsys_data", "./my_program"]
    stats_command = ["nsys", "stats", "nsys_data.nsys-rep", ">", "nsys_data_output.txt"]

    print(f"Executing: {' '.join(profile_command)}")
    subprocess.run(profile_command, check=True)

    print(f"Executing: {' '.join(stats_command)}")
    subprocess.run(stats_command, shell=True, check=True)  

def func_time():
    function_offset_names = defaultdict(int)

    with open("perf_script.txt","r") as f:
        for line in f:
            function_offset_names[line.split()[-2]] += 1
    
    function_names = defaultdict(int)

    sample_sum = 0
    for key, value in function_offset_names.items():
        function_names[key.split('+')[0]] += value
        sample_sum += value
        
    percentages = {key: round((value / sample_sum) * 100, 2) for key, value in function_names.items()}
    sorted_function = sorted(percentages.items(), key=lambda item: item[1], reverse=True)

    with open("func_time.txt", "w") as output_file:
        for func, percentage in sorted_function:
            output_file.write(f"{func}\t{percentage}\n")

    return sorted_function

def run_gdb_disassemble(executable, function_name="main"):
    output_file = f"{function_name}_output.txt"
    gdb_commands = f"""
    set logging enabled on
    disassemble /m {function_name}
    set logging enabled off
    """
    
    try:
        with open(output_file, 'w') as log_file:
            process = subprocess.Popen(
                ["gdb", executable],
                stdin=subprocess.PIPE,   
                stdout=log_file,         
                stderr=subprocess.PIPE   
            )
            process.communicate(input=gdb_commands.encode())

    except Exception as e:
        print(f"Error occurred: {e}")

def process_source_code_and_assemble(input_file_1, function_name="main"):
    #step1: read the perf_script.txt and count the functions cpu-cycles
    offset_counts = defaultdict(int)

    pattern = re.compile(rf'{re.escape(function_name)}\+0x([0-9a-fA-F]+)')

    total_count = 0
    with open(input_file_1, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                offset = match.group(1)
                offset_counts[offset] += 1
                total_count += 1

    sorted_offsets = sorted(offset_counts.items(), key=lambda x: x[1], reverse=True)

    offset_dict = {}
    for offset, count in sorted_offsets:
        proportion = count / total_count
        offset_dict[f"0x{offset}"] = round(proportion, 3)
    #step2:read the gdb.txt and count each code's cpu-cycles
    input_file_2 = f"{function_name}_output.txt"
    source_code_counts = []

    source_code_pattern = re.compile(r'^\d+\s+(.+)')

    with open(input_file_2, 'r') as f:
        current_source_code = None
        current_offsets = []

        for line in f:
            source_match = source_code_pattern.match(line)
            if source_match:
                if current_source_code:
                    total_count = 0
                    for offset in current_offsets:
                        hex_offset = hex(offset)
                        if hex_offset in offset_dict:
                            total_count += offset_dict[hex_offset]
                    source_code_counts.append((current_source_code, total_count))
                
                current_source_code = source_match.group(1).strip()
                current_offsets = [] 

            offset_match = re.search(r'<\+(\d+)>', line)
            if offset_match:
                offset = int(offset_match.group(1))  
                current_offsets.append(offset)

        if current_source_code:
            total_count = 0
            for offset in current_offsets:
                hex_offset = hex(offset)
                if hex_offset in offset_dict:
                    total_count += offset_dict[hex_offset]
            source_code_counts.append((current_source_code, total_count))

    output_file = f"{function_name}_cycles_count.txt"
    with open(output_file, 'w') as out_f:
        for source_code, count in source_code_counts:
            if count > 0:
                out_f.write(f"{count * 100:.2f}%\t{source_code}\n")
            else:
                out_f.write(f"\t{source_code}\n")

def read_txt_files(file_paths):
    data = {}
    
    for file_path in file_paths:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                content = file.readlines()
                data[file_path] = [line for line in content]

    with open("combined_data.json", 'w') as json_file:
        json.dump(data, json_file, indent=4)

def monitor_process_memory(executable_path, sample_hz=10, mem_sample_file_path="mem_sample.txt"):

    process = subprocess.Popen([executable_path])
    pid = process.pid

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

    process.wait()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run perf commands with a given executable file")
    parser.add_argument("executable", help="Path to the executable file")
    parser.add_argument("-p", "--program-args", type=str, default="", 
                        help="Arguments to pass to the executable program")
    parser.add_argument("-f", "--frequency", type=int, default=10, 
                        help="Sampling frequency for monitor_process_memory (default: 10 Hz)")
    parser.add_argument("-r", "--interval", type=float, default=1.0, 
                        help="Interval for the read command (default: 1.0)")
    args = parser.parse_args()

    if check_bcc_library():
        first_record(args.executable, args.program_args)
        second_record(args.executable, args.program_args)
    else:
        run_perf_commands(args.executable)
        run_perf_stat_commands(args.executable)
        monitor_process(args.executable, args.interval)
        monitor_process_memory(args.executable, sample_hz=args.frequency)

    if check_nsys_installed():
        run_nsys_profile_and_stats()
    else:
        print("Warning: Get the gpu data needs the nsys tool, you should install cuda.")

    txt_files = ["perf_stat.txt", "get_active_page_data.txt", "net_flow.txt", "nsys_data_output.txt", "mem_sample.txt", "load_data.txt", "func_time.txt"]
    temp_files = []
    sorted_function = func_time()
    for func_name, proportion in sorted_function[:3]:
        if proportion > 10:
            run_gdb_disassemble(args.executable, func_name)
            process_source_code_and_assemble('perf_script.txt', func_name)
            txt_files.append(f"{func_name}_cycles_count.txt")
            temp_files.append(f"{func_name}_output.txt")
    
    read_txt_files(txt_files)

    txt_files.append("gdb.txt")
    txt_files.append("perf.data")
    txt_files.append("tmp_start.txt")
    txt_files.append("perf_script.txt")
    txt_files.append("execve_start.txt")
    txt_files.extend(temp_files)
    
        # delete the temp files
    for file_name in txt_files:
        try:
            os.remove(file_name)
        except Exception as e:
            print(f"Error deleting {file_name}: {e}")