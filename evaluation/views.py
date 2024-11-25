from django.shortcuts import render
from collections import defaultdict
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
from django.http import HttpResponse
import re
import json
import os

def index(request):
    return HttpResponse("Hello, world. You're at the evalution index.")

# 获取函数耗时排行数据
def func_time(data):
    # (函数名+偏移量：采样数)的字典
    # 此处的函数名是“函数名+偏移量”的形式，如main+0x164
    function_offset_names = defaultdict(int)
    
    # 获取perf script文件的每一行的函数名(下标为-2的子串),递增计数
    # 此处的函数名是“函数名+偏移量”的形式，如main+0x164
    # TODO:使用偏移量分析某行汇编代码的使用
    file_name = "perf_script.txt"
    if file_name in data:
        for line in data[file_name]:
            function_offset_names[line.split()[-2]] += 1
    
    function_names = defaultdict(int)

    # 统计函数名，记录在(函数名：采样数)字典中
    # 记录全部样本数量，之后将采样数转为百分比
    sample_sum = 0
    for key, value in function_offset_names.items():
        function_names[key.split('+')[0]] += value
        sample_sum += value
        
    # 将结果从大到小排序
    # 计算每个值占总和的百分比
    percentages = {key: round((value / sample_sum) * 100, 2) for key, value in function_names.items()}
    sorted_function = sorted(percentages.items(), key=lambda item: item[1], reverse=True)

    return sorted_function

# 根据perf stat文件，获取各项指标
def perf_stat_analyze(data):
    results = {}
    #with open("perf_stat.txt", "r") as f:
    file_name = "perf_stat.txt"
    if file_name in data:
        for line in data[file_name]:
        #for line in f:
            # 匹配事件统计数据的行
            match = re.match(r'^\s*([\d,.]+)\s+(\S+)\s(\S*)', line)
            if match:
                count = match.group(1).replace(',', '')  # 去掉逗号，保留数字
                event = match.group(2).replace('-','_')  # 事件名称
                second_event = match.group(3)
                if (second_event == "time" or second_event == "user" 
                    or second_event == "sys" or second_event == "task-clock"):
                    results[second_event] = round(float(count),2)
                else :
                    results[event] = count
    results['cache_misses_rate'] = round(int(results['cache_misses']) / int(results['cache_references']) * 100, 2)
    results['branch_misses_rate'] = round(int(results['branch_misses']) / int(results['branches']) * 100, 2)
    results['inst_per_cycle'] = round(int(results['instructions']) / int(results['cycles']), 2)
    results['cpu_util'] = round((float((results['user']))+float(results['sys'])) / float(results['time']) * 100, 1)
    
    return results

# 根据物理内存采样数据，获得最大内存使用，并绘制内存使用情况图
def rss_mem_used(data):
    if "mem_sample.txt" in data:
        lines = data["mem_sample.txt"]

    max_value = 0
    
    for line in lines:
        value = int(line.strip())
        if value > max_value:
            max_value = value

    # max_value以kb为单位
    return max_value

def mem_samples():
# 从 JSON 文件中读取数据
    with open("combined_data.json", "r") as json_file:
        data = json.load(json_file)

    # 获取 mem_sample.txt 对应的数据
    if "mem_sample.txt" in data:
        lines = data["mem_sample.txt"]
    
    total_lines = len(lines)
    sample_points = [0,]
    
    for index, line in enumerate(lines):
        # 计算采样点位置
        if index % (total_lines // 10) == 0:
            sample_points.append(int(line.strip()))

    return sample_points

def get_total_traffic(data):
        # 打开文件并读取所有行
    if "net_flow.txt" in data:
        lines = data["net_flow.txt"]

    if not lines:
        return "No data available"

    # 获取最后一行并提取最后一个值
    last_line = lines[-1].strip()  # 移除行尾的换行符和空白
    total_traffic = last_line.split()[-1]  # 获取最后一个数据项

    return total_traffic

def extract_gpu_kernel_summary(data):
    # 结果数组，用于存储处理后的数据
    results = {}
    if "nsys_data_output.txt" in data:
        lines = data["nsys_data_output.txt"]

    capture = False

    for line in lines:
        # 当遇到 "CUDA GPU Kernel Summary" 时开始捕获数据
        if "CUDA GPU Kernel Summary" in line:
            capture = True
            continue

        # 当遇到 "CUDA GPU MemOps Summary" 时停止捕获数据
        if capture and "CUDA GPU MemOps Summary" in line:
            break

        # 忽略空行或者没有有效数据的行
        if capture and line.strip() == "":
            continue

        # 提取占用百分比和函数名
        if capture:
            # 匹配并提取占用百分比（行首浮动数字）
            percentage_match = re.match(r"\s*(\d+\.\d+)\s+.*", line)
            if percentage_match:
                occupancy_percentage = float(percentage_match.group(1))

                # 分割字符串，提取第二个 "::" 后的内容
                parts = line.split("::", 2)
                if len(parts) >= 3:
                    # 如果第二个部分以 "<" 开头，检查长度后决定是否使用 parts[3]
                    if parts[2].strip().startswith('<'):
                        temp = parts[2].split("::", 1)
                        function_name = temp[1]
                    else:
                        function_name = parts[2].strip()  # 获取第二个 "::" 后的部分
                else:
                    function_name = line.strip().split()[-1]  # 如果没有第二个 "::"，取最后一个词
                # 将提取的函数名和占用百分比添加到结果中
                results[function_name] = occupancy_percentage

    sorted_functions = sorted(results.items(), key=lambda item: item[1], reverse=True)
    result = [(func, round(percentage, 2)) for func, percentage in sorted_functions]
    # 返回的结果是包含多个字典的数组，每个字典表示一个函数和它的占用百分比
    return result

def read_main_cycles():
    try:
        # 打开文件并读取代码
        with open("code_cycles_count.txt", "r") as file:
            code = file.read()
        
        return code

    except FileNotFoundError:
        return "File not found"

def load_json(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)

def runningdata(request):
    ret_dict = {}
    data = load_json("combined_data.json")

    perf_stat_data = perf_stat_analyze(data)
    ret_dict["perfStat"] = perf_stat_data

    # 函数时间排行
    ret_dict["functionTime"] = func_time(data)

    #GPU内核函数耗时排行
    ret_dict["GPU_kernel_time"] = extract_gpu_kernel_summary(data)

    # 最大内存使用和内存使用情况采样
    max_rss_memory = rss_mem_used(data)
    if int(max_rss_memory > (1024 *1024)):
        ret_dict["max_memory_uesd"] = str(round(max_rss_memory / (1024 * 1024), 2)) + "GB"
    elif int(max_rss_memory > 1024):
        ret_dict["max_memory_uesd"] = str(round(max_rss_memory / 1024, 2)) + "MB"
    else:
        ret_dict["max_memory_uesd"] = str(max_rss_memory) + "kB"

    ret_dict["total_traffic"] = get_total_traffic(data) + "KB"

    ret_dict["main_code_count"] = read_main_cycles()
    
    return JsonResponse(ret_dict)

def get_mem_samples(request):
    ret_dict = {}
    mem_samples_points = mem_samples()
    ret_dict["mem_samples"] = mem_samples_points
    return JsonResponse(ret_dict)

def get_active_pages(request):
    ret_dict = {}
    # 从文件读取数据
    with open("combined_data.json", "r") as json_file:
        json_data = json.load(json_file)
    
    data = json_data.get("get_active_page_data.txt", "")
    if isinstance(data, list):
        data = "".join(data) 

    # 使用正则表达式提取数据并累加
    pattern = r"Filename:(\S+)\s+Range:\s([0-9a-fA-F]+-[0-9a-fA-F]+)\s+Memory Size:\s([\d.]+)\s+MB\s+Active Pages:\s(\d+)"
    memory_data = defaultdict(lambda: defaultdict(lambda: {"Memory Size": 0, "Active Pages": 0}))

    for match in re.finditer(pattern, data):
        filename = match.group(1)
        range_key = match.group(2)
        memory_size = float(match.group(3))
        active_pages = int(match.group(4))

    # 只记录第一次提取到的Memory Size，并累加Active Pages
        if memory_data[filename][range_key]["Memory Size"] == 0:
            memory_data[filename][range_key]["Memory Size"] = memory_size
        memory_data[filename][range_key]["Active Pages"] += active_pages

    # 汇总所有的内存数据
    all_data = []
    for filename, ranges in memory_data.items():
    # 排除 [anno] 文件名
        if filename != "[anno]":
            # 对每个文件名，只保留 Active Pages 最大的一个范围
            max_active_pages_info = None
            for range_key, info in ranges.items():
                if max_active_pages_info is None or info["Active Pages"] > max_active_pages_info["Active Pages"]:
                    max_active_pages_info = info
            if max_active_pages_info:
                all_data.append({
                    "Filename": filename,
                    "Range": range_key,
                    "Memory Size": max_active_pages_info["Memory Size"],
                    "Active Pages": max_active_pages_info["Active Pages"]
                })

    # 按Active Pages数量排序
    sorted_data = sorted(all_data, key=lambda x: x["Active Pages"], reverse=True)

    # 取前10条数据
    top_10_data = sorted_data[:10]

    # 累加前10条数据的Active Pages总大小
    total_active_pages = sum(item["Active Pages"] for item in top_10_data) if top_10_data else 1

    # 创建两个空数组，分别存储 Filename 和 Normalized Active Pages
    File_Name = []  # 存储 Filename
    active_pages_Nor = []   # 存储 Normalized Active Pages

    # 填充数组
    for i, info in enumerate(top_10_data):
        # 截取 '.so' 后面的版本号
        filename = info['Filename']
        filename = re.sub(r'\.so(\.\d+(\.\d+)*)$', '.so', filename)  # 使用正则表达式替换版本号部分

        normalized_active_pages = round(info["Active Pages"] / total_active_pages, 2)
        File_Name.append(filename)
        active_pages_Nor.append([i,0,normalized_active_pages])


    ret_dict["file_name"] = File_Name
    ret_dict["active_pages_Nor"] = active_pages_Nor
    # 输出结果（可选）
    print("other_points:", active_pages_Nor)
    return JsonResponse(ret_dict)

def function_details(request, function_name):
    print(function_name)
    with open("combined_data.json", 'r') as json_file:
        data = json.load(json_file)
    
    tmp_name = f"{function_name}_cycles_count.txt"
    if tmp_name in data:
        code = ''.join(([line for line in data[tmp_name]]))
        
        return JsonResponse({
        'code': code,  
    })

@csrf_exempt
def file_upload(request):
    if request.method == 'POST':
        print(os.getcwd())
        try:
            # 检查是否提供了文件
            json_file = request.FILES.get('file')
            if not json_file:
                return JsonResponse({'error': 'No file uploaded'}, status=400)
            
            # 将文件内容保存到combined_data.json
            save_path = os.path.join(os.getcwd(), 'combined_data.json')  # 当前文件夹路径
            with open(save_path, 'w', encoding='utf-8') as destination:
                for chunk in json_file.chunks():
                    destination.write(chunk.decode('utf-8'))  # 解码为字符串并写入
            
            file_url = f"/{os.path.basename(save_path)}"
            return JsonResponse({'message': 'File saved successfully', 'url': request.build_absolute_uri(file_url)})
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)