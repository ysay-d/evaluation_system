from django.shortcuts import render
from collections import defaultdict
from django.http import JsonResponse

# Create your views here.
from django.http import HttpResponse
import re

def index(request):
    return HttpResponse("Hello, world. You're at the evalution index.")

# 获取函数耗时排行数据
def func_time():
    # (函数名+偏移量：采样数)的字典
    # 此处的函数名是“函数名+偏移量”的形式，如main+0x164
    function_offset_names = defaultdict(int)
    
    # 获取perf script文件的每一行的函数名(下标为-2的子串),递增计数
    # 此处的函数名是“函数名+偏移量”的形式，如main+0x164
    # TODO:使用偏移量分析某行汇编代码的使用
    with open("perf_script.txt","r") as f:
        for line in f:
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
def perf_stat_analyze():
    results = {}
    with open("perf_stat.txt", "r") as f:
        for line in f:
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
def rss_mem_used():
    with open("mem_sample.txt", "r") as f:
        lines = f.readlines()

    max_value = 0
    
    for line in lines:
        value = int(line.strip())
        if value > max_value:
            max_value = value

    # max_value以kb为单位
    return max_value

def mem_samples():
    with open("mem_sample.txt", "r") as f:
        lines = f.readlines()
    
    total_lines = len(lines)
    sample_points = [0,]
    
    for index, line in enumerate(lines):
        # 计算采样点位置
        if index % (total_lines // 10) == 0:
            sample_points.append(int(line.strip()))

    return sample_points

def runningdata(request):
    ret_dict = {}

    perf_stat_data = perf_stat_analyze()
    ret_dict["perfStat"] = perf_stat_data

    # 函数时间排行
    ret_dict["functionTime"] = func_time()

    # 最大内存使用和内存使用情况采样
    max_rss_memory = rss_mem_used()
    if int(max_rss_memory > (1024 *1024)):
        ret_dict["max_memory_uesd"] = str(round(max_rss_memory / (1024 * 1024), 2)) + "GB"
    elif int(max_rss_memory > 1024):
        ret_dict["max_memory_uesd"] = str(round(max_rss_memory / 1024, 2)) + "MB"
    else:
        ret_dict["max_memory_uesd"] = str(max_rss_memory) + "kB"

    return JsonResponse(ret_dict)

def get_mem_samples(request):
    ret_dict = {}
    mem_samples_points = mem_samples()
    ret_dict["mem_samples"] = mem_samples_points
    return JsonResponse(ret_dict)