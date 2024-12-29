package main

import (
	"flag"
	"fmt"
	"hello/Assist"
	"os"
	"strconv"
	"sync"
)

var (
	mutex         sync.Mutex
	errorCounters map[string]int
)

func main() {
	// 定义命令行参数
	domain := flag.String("d", "", "输入的单个域名")
	domainListFile := flag.String("l", "", "输入的域名列表文件")
	poolSizeStr := flag.String("p", "1", "线程池大小")
	mod := flag.Int("mod", 1, "模式: 1 表示画图, 2 表示生成对应的 json 文件, 3 表示只分类不画图也不生成 json 文件,4 只测拓扑，也不生成 csv 文件")
	outputFile := flag.String("output", "dns_errors.csv", "输出的CSV文件名")
	ipVersion := flag.Int("v", 0, "IP版本: 4 表示 IPv4, 6 表示 IPv6, 其他表示同时使用 IPv4 和 IPv6")

	// 解析命令行参数
	flag.Parse()

	// 检查线程池大小的有效性
	poolSize, err := strconv.Atoi(*poolSizeStr)
	if err != nil || poolSize <= 0 {
		fmt.Printf("Invalid pool size: %v\n", err)
		os.Exit(1)
	}

	// 检查输入参数
	if *domain == "" && *domainListFile == "" {
		fmt.Printf("Usage: %s [-d <domain>] [-l <domainlist_file>] [-p <pool_size>] [-mod <mode>] [-output <output_file>] [-v <ip_version>]\n", os.Args[0])
		os.Exit(1)
	}

	// 根据输入参数执行不同的逻辑
	if *domain != "" {
		Assist.HandleSingleDomain(*domain, *mod,*ipVersion)
	} else if *domainListFile != "" {
		Assist.HandleDomainList(*domainListFile, poolSize, *mod, *outputFile,*ipVersion)
	}
}
