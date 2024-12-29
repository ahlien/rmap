#!/bin/bash

# # Define the domain list
# domain_list="domain.csv"

# # Define the output file prefix based on the domain list date (if applicable)
# output_prefix="domain_dump"

# # Define the list of resolvers to use
# resolvers=(
#     "8.8.8.8:53"
#     "1.1.1.1:53"
#     "9.9.9.9:53"
#     "208.67.222.222:53"
#     "77.88.8.8:53"
# )

# # Define corresponding names for each resolver for output file naming
# resolver_names=(
#     "google_dns"
#     "cloudflare_dns"
#     "quad9_dns"
#     "opendns"
#     "yandex_dns"
# )

# # Loop over each resolver
# for i in "${!resolvers[@]}"; do
#     resolver="${resolvers[i]}"
#     resolver_name="${resolver_names[i]}"

#     echo "Starting query for $domain_list with resolver $resolver"

#     # Run the command and redirect output to a log file
#     # Since we're not using nohup, it will wait for the command to finish
#     ./query2 -input "$domain_list" -resolver "$resolver" -output "${output_prefix}_${resolver_name}.csv" > "${output_prefix}_${resolver_name}.log" 2>&1

#     echo "Finished query for $domain_list with resolver $resolver"
# done



#!/bin/bash

# 定义文件、参数和可执行文件
files=("test_10000.txt" "test_10000.txt")
params=(1000)
executables=("cache" "nocache" ) # 假设这两个是编译好的Go可执行文件

# 循环遍历每个可执行文件
for exe in "${executables[@]}"; do
    # 循环遍历每个文件
    for file in "${files[@]}"; do
        # 循环遍历每个参数
        for param in "${params[@]}"; do
            # 构造输出和日志文件名
            output_file="${file%.txt}_result_${param}_${exe}.csv"
            log_file="${file%.txt}_output_${param}_${exe}.log"
            
            # 执行命令并将其放入后台
            nohup ./$exe -l $file -mod 3 -output $output_file -p $param > $log_file 2>&1 &
            
            # 打印执行的命令
            echo "Running: nohup ./$exe -l $file -mod 3 -output $output_file -p $param > $log_file 2>&1 &"
            
            # 添加日志标签
            echo "Log: Executed $exe with $file and param $param" >> $log_file
        done
    done
done

echo "All tasks have been started."