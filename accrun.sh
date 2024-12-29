#!/bin/bash

# 定义文件名和参数数组
files=("domain1.txt" "domain10.txt" "domain100.txt" "domain200.txt")
params=("10" "100" "200")
programs=("./nocache")


# 构建命令
command="./nocache -l domain10.txt -mod 3 -p 10"
# 打印即将执行的命令
echo "Executing: $command"
# 使用`time`命令测量执行时间
{ time $command; } 2>&1 | grep real

# 构建命令
command="./nocache -l domain100.txt -mod 3 -p 100"
# 打印即将执行的命令
echo "Executing: $command"
# 使用`time`命令测量执行时间
{ time $command; } 2>&1 | grep real


# 构建命令
command="./nocache -l domain200.txt -mod 3 -p 200"
# 打印即将执行的命令
echo "Executing: $command"
# 使用`time`命令测量执行时间
{ time $command; } 2>&1 | grep real





