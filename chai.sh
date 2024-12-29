#!/bin/bash

# 配置参数
FILES=("domain1.txt" "domain2.txt" "domain3.txt" "domain4.txt" "domain5.txt" "domain6.txt" "domain7.txt" "domain8.txt" "domain9.txt" "domain10.txt")
LOG_DIR="./logs"       # 日志存储目录
COMMAND="go run ipv6test.go -mod 4 -p 500"

# 创建日志目录
mkdir -p "$LOG_DIR"

# 循环处理每个文件
for FILE in "${FILES[@]}"; do
    # 提取文件名以生成对应日志文件名
    BASENAME=$(basename "$FILE" .txt)
    LOG_FILE="${LOG_DIR}/${BASENAME}.log"

    echo "正在处理 $FILE，输出到 $LOG_FILE"

    # 执行命令，将输出重定向到日志文件
    $COMMAND -l "$FILE" > "$LOG_FILE" 2>&1

    # 检查命令是否成功执行
    if [[ $? -eq 0 ]]; then
        echo "$FILE 处理完成，日志已保存到 $LOG_FILE"
    else
        echo "处理 $FILE 时出错，请检查 $LOG_FILE"
    fi
done

echo "所有任务已完成！"
