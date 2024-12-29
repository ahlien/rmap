#!/bin/bash

# 循环从 1 到 29
for i in {1..29}
do
  # 构造命令字符串
  cmd="go run test.go -l domainlist_part_${i}.txt -p 1500 -output result.csv -mod 3 >output_${i}.log"
  
  # 输出当前执行的命令
  echo "Executing: $cmd"
  
  # 在后台执行命令
  eval $cmd &
  
  # 获取后台进程的PID
  pid=$!
  
  # 等待当前后台进程完成
  wait $pid
  
  # 检查命令是否成功
  if [ $? -eq 0 ]; then
    echo "Command for domainlist_part_${i}.txt completed successfully."
  else
    echo "Command for domainlist_part_${i}.txt failed."
    # 如果需要的话，你可以选择在失败时退出脚本
    # exit 1
  fi
done

echo "All commands executed."