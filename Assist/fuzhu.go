// 辅助模块，对错误或异常进行分类，可根据自己的测量需求进行扩展

package Assist

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"hello/pkg/Cache"
	"hello/pkg/Graph"
	"hello/pkg/Resolver"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func writeErrorsToCSV(domain string, cache Cache.DNSCache, fileName string, mutex *sync.Mutex, errorCounters map[string]int) {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if the file is empty
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("Error getting file info: %v\n", err)
		return
	}

	// 动态生成头部
	if fileInfo.Size() == 0 {
		header := []string{"domain"}
		e := reflect.ValueOf(&cache.Errors).Elem()
		for i := 0; i < e.NumField(); i++ {
			header = append(header, e.Type().Field(i).Name)
		}
		writer.Write(header)
	}


	// 动态生成记录
	record := []string{domain}
	// e := reflect.ValueOf(&cache.Errors).Elem()
	// for i := 0; i < e.NumField(); i++ {
	// 	record = append(record, anyToStr(e.Field(i)))
	// }
	e := reflect.ValueOf(cache.Errors)
	for i := 0; i < e.NumField(); i++ {
		field := e.Field(i)
		record = append(record, anyToStr(field))
	}
	writer.Write(record)

	// 更新错误计数器
	updateErrorCounters(cache.Errors, errorCounters)
}

// intToStr 将整数转换为字符串
func intToStr(i int) string {
	return strconv.Itoa(i)
}

// anyToStr 根据类型将任意值转换为字符串
func anyToStr(value reflect.Value) string {

	if value.Kind()==reflect.Bool{
		return boolToStr(value.Bool())
	}else{
		return intToStr(int(value.Int()))
	}
	// switch value.Kind() {
	// case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	// 	return intToStr(int(value.Int()))
	// case reflect.Bool:
	// 	return boolToStr(value.Bool())
	// // 你可以根据需要添加更多类型的处理
	// default:
	// 	return fmt.Sprintf("%v", value)
	// }
}


func HandleSingleDomain(domain string, mod int,version int) {
	switch mod {
	case 1:
		fmt.Printf("Handling single domain %s to draw graph.\n", domain)
		// 调用绘图逻辑
	case 2:
		fmt.Printf("Handling single domain %s to generate JSON.\n", domain)
		// 调用生成 JSON 文件逻辑
		processSingleDomain(domain,version)

	case 3:
		fmt.Printf("Handling single domain %s to classify.\n", domain)
		// 调用分类逻辑
	default:
		fmt.Printf("Invalid mode: %d\n", mod)
		os.Exit(1)
	}
}

func HandleDomainList(domainListFile string, poolSize int, mod int, outputFile string, version int) {
	switch mod {
	case 1:
		fmt.Printf("Handling domain list from %s with pool size %d to draw graph.\n", domainListFile, poolSize)
		// 调用绘图逻辑
	case 2:
		fmt.Printf("生成域名对应的JSON文件.\n")
		// 调用生成 JSON 文件逻辑
		processDomainList_json(domainListFile, poolSize, outputFile,version)
	case 3:
		fmt.Printf("Handling domain list from %s with pool size %d to classify.\n", domainListFile, poolSize)
		// 调用分类逻辑
		processDomainList_csv(domainListFile, poolSize, outputFile,version)
	case 4:
		fmt.Printf("Handling domain list from %s with pool size %d to identify nameservers.\n", domainListFile, poolSize)
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	case 5:
		fmt.Printf("Handling domain list from %s with pool size %d to identify nameservers.\n", domainListFile, poolSize)
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	case 6:
		fmt.Printf("Handling domain list from %s with pool size %d to identify AAAA Records.\n", domainListFile, poolSize)
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	case 7:
		fmt.Printf("探测域名解析拓扑，输出边和节点信息。\n")
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	case 8:
		fmt.Printf("探测域名所依赖的所有 IPv6 权威域名服务器\n")
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	case 9:
		fmt.Printf("探测可能被用于流量放大的解析链\n")
        idauthoritynameserver(domainListFile, poolSize, outputFile,version,mod)
	default:
		fmt.Printf("Invalid mode: %d\n", mod)
		os.Exit(1)
	}
}

// func processDomain(domain string, wg *sync.WaitGroup, outputFile string, mutex *sync.Mutex, errorCounters map[string]int) {
// 	defer wg.Done()

// 	cc := Cache.NewDNSCache(domain)
// 	gg := Graph.NewGraph(domain)

// 	var dig Resolver.Dig
// 	err := dig.Trace(domain, dns.TypeA, gg, cc)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	handleGraphAndCache(domain, gg, cc)
// 	writeErrorsToCSV(domain, *cc, outputFile, mutex, errorCounters)
// }

func processDomainList_json(domainListFile string, poolSize int, outputFile string, version int) {
	file, err := os.Open(domainListFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, poolSize)
	startTime := time.Now()
	var domainCount int
	milestone := 10000
	milestoneTime := startTime
	var mutex sync.Mutex
	for scanner.Scan() {
		domain := scanner.Text()
		domainCount++

		//var dig Resolver.Dig
		semaphore <- struct{}{}
		wg.Add(1)

		go func(domain string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			cc := Cache.NewDNSCache(domain,version) // 假设这是一个初始化 DNSCache 的函数
			gg := Graph.NewGraph(domain)    // 假设这是一个初始化 GraphGraph 的函数

			var dig Resolver.Dig // 使用指针初始化 Dig
			dig.Trace(domain, dns.TypeA, gg, cc, &mutex,0) // 传递 mutex 指针

			handleGraphAndCache(domain, gg, cc)
		}(domain)

		if domainCount%milestone == 0 {
			currentTime := time.Now()
			fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
			milestoneTime = currentTime
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	wg.Wait()
	totalTime := time.Since(startTime)
	fmt.Printf("All domains have been resolved in %v\n", totalTime)
}


func idauthoritynameserver(domainListFile string, poolSize int, outputFile string,version int,mod int) {
	file, err := os.Open(domainListFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, poolSize)
	startTime := time.Now()
	var domainCount int
	milestone := 10000
	milestoneTime := startTime

	// 初始化错误计数器
	errorCounters := make(map[string]int)
	var mutex sync.Mutex

	for scanner.Scan() {
		domain := scanner.Text()
		domainCount++

		//var dig Resolver.Dig
		semaphore <- struct{}{}
		wg.Add(1)

		go func(domain string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			cc := Cache.NewDNSCache(domain,version) // 假设这是一个初始化 DNSCache 的函数
			gg := Graph.NewGraph(domain)    // 假设这是一个初始化 GraphGraph 的函数

			var dig Resolver.Dig // 使用指针初始化 Dig
			dig.Trace(domain, dns.TypeA, gg, cc, &mutex,mod) // 传递 mutex 指针
			
			writeErrorsToCSV(domain, *cc, outputFile, &mutex, errorCounters)
		}(domain)

		// if domainCount%milestone == 0 {
		// 	currentTime := time.Now()
		// 	fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
		// 	milestoneTime = currentTime
		// }
		if domainCount%milestone == 0 {
			currentTime := time.Now()
			fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
			milestoneTime = currentTime
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	wg.Wait()
	totalTime := time.Since(startTime)
	fmt.Printf("All domains have been resolved in %v\n", totalTime, domainListFile)
}

func processDomainList_csv(domainListFile string, poolSize int, outputFile string,version int) {
	file, err := os.Open(domainListFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, poolSize)
	startTime := time.Now()
	var domainCount int
	milestone := 10000
	milestoneTime := startTime

	// 初始化错误计数器
	errorCounters := make(map[string]int)
	var mutex sync.Mutex

	for scanner.Scan() {
		domain := scanner.Text()
		domainCount++

		//var dig Resolver.Dig
		semaphore <- struct{}{}
		wg.Add(1)

		go func(domain string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			cc := Cache.NewDNSCache(domain,version) // 假设这是一个初始化 DNSCache 的函数
			gg := Graph.NewGraph(domain)    // 假设这是一个初始化 GraphGraph 的函数

			var dig Resolver.Dig // 使用指针初始化 Dig
			dig.Trace(domain, dns.TypeA, gg, cc, &mutex,0) // 传递 mutex 指针
			
			writeErrorsToCSV(domain, *cc, outputFile, &mutex, errorCounters)
		}(domain)

		// if domainCount%milestone == 0 {
		// 	currentTime := time.Now()
		// 	fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
		// 	milestoneTime = currentTime
		// }
		if domainCount%milestone == 0 {
			currentTime := time.Now()
			fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
			milestoneTime = currentTime
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	wg.Wait()
	totalTime := time.Since(startTime)
	fmt.Printf("All domains have been resolved in %v\n", totalTime, domainListFile)

	// 在所有域名解析完成后，写入统计信息
	writeStatisticsToCSV(outputFile, &mutex, errorCounters)
}

// func processDomainList(domainListFile string, poolSize int, outputFile string) {
// 	file, err := os.Open(domainListFile)
// 	if err != nil {
// 		fmt.Printf("Error opening domain list file: %s\n", err)
// 		return
// 	}
// 	defer file.Close()

// 	var wg sync.WaitGroup
// 	var mutex sync.Mutex
// 	errorCounters := make(map[string]int)
// 	domainCount := 0
// 	milestone := 100 // 假设每 100 个域名打印一次里程碑
// 	milestoneTime := time.Now()

// 	// 创建协程池
// 	pool, _ := ants.NewPoolWithFunc(poolSize, func(i interface{}) {
// 		domain := i.(string)
// 		processDomain(domain, &wg, outputFile, &mutex, errorCounters)
// 	})
// 	defer pool.Release()

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		domain := scanner.Text()
// 		domainCount++

// 		wg.Add(1)
// 		_ = pool.Invoke(domain)

// 		if domainCount%milestone == 0 {
// 			currentTime := time.Now()
// 			fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
// 			milestoneTime = currentTime
// 		}
// 	}
// 	if err := scanner.Err(); err != nil {
// 		fmt.Printf("Error reading domain list file: %s\n", err)
// 		return
// 	}

// 	wg.Wait()
// }

func processSingleDomain(domain string,version int) {
	startTime := time.Now()
	cc := Cache.NewDNSCache(domain,version) // 假设这是一个初始化 DNSCache 的函数
	gg := Graph.NewGraph(domain)    // 假设这是一个初始化 GraphGraph 的函数

	//var dig Resolver.Dig
	// dig.Trace(domain, dns.TypeA, gg, cc)
	handleGraphAndCache(domain, gg, cc)

	totalTime := time.Since(startTime)
	fmt.Printf("All domains have been resolved in %v\n", totalTime)
}

func handleGraphAndCache(domain string, gg *Graph.DNSGraph, cc *Cache.DNSCache) {
	// 检测循环引用并处理错误
	// OneCircularRef, MultiCircularRef := gg.DetectCycles()
	// if MultiCircularRef {
	// 	cc.SetError("MultiCircularRef")
	// }
	// if OneCircularRef {
	// 	cc.SetError("OneCircularRef")
	// }
    fmt.Println(gg.HasSelfLoop())


	gg.AssignLevels()

	// 将图转换为JSON格式
	jsonData := gg.ToJSON()

	// 确定文件存储路径
	storePath := filepath.Join(".", "pkg", "visual", "store")
	err := os.MkdirAll(storePath, os.ModePerm)
	if err != nil {
		panic(err)
	}

	// 创建并写入文件
	domainName := strings.ReplaceAll(domain, ".", "_")
	jsonFileName := fmt.Sprintf("%s.json", domainName)
	jsonFilePath := filepath.Join(storePath, jsonFileName)
	writeToFile(jsonFilePath, jsonData)

	fmt.Println("Graph JSON data has been written to", jsonFilePath)

	cc.SaveCacheToJSON(storePath)
}

func writeToFile(filePath string, data string) {
	file, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		panic(err)
	}
}

// updateErrorCounters 更新错误计数器
func updateErrorCounters(errors Cache.ERROR, errorCounters map[string]int) {
	v := reflect.ValueOf(errors)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if v.Field(i).Bool() {
			errorCounters[field.Name]++
		}
	}
}

// func updateErrorCounters(errors Cache.ERROR, errorCounters map[string]int) {
// 	if errors.TimeoutOccurred {
// 		errorCounters["TimeoutOccurred"]++
// 	}
// 	if errors.RecursionAvailable {
// 		errorCounters["RecursionAvailable"]++
// 	}
// 	if errors.SOAInAuthority {
// 		errorCounters["SOAError"]++
// 	}
// 	if errors.CNAMECircularRef {
// 		errorCounters["CNAMECircularRef"]++
// 	}
// 	if errors.NsInAnswerFound {
// 		errorCounters["NsInAnswerFound"]++
// 	}
// 	if errors.PacketFormatError {
// 		errorCounters["PacketFormatError"]++
// 	}
// 	if errors.SOAInAnswerFound {
// 		errorCounters["SOAInAnswerFound"]++
// 	}
// 	if errors.OPTError {
// 		errorCounters["OPTError"]++
// 	}
// 	if errors.SuccessfullyParsed {
// 		errorCounters["SuccessfullyParsed"]++
// 	}
// 	if errors.MultiCircularRef {
// 		errorCounters["MultiCircularRef"]++
// 	}
// 	if errors.OneCircularRef {
// 		errorCounters["OneCircularRef"]++
// 	}
// 	if errors.InvalidIP {
// 		errorCounters["InvalidIP"]++
// 	}
// 	if errors.IPv4Reserved {
// 		errorCounters["IPv4Reserved"]++
// 	}
// 	if errors.IPv6Reserved {
// 		errorCounters["IPv6Reserved"]++
// 	}
// 	if errors.NoErrorQuery {
// 		errorCounters["NoErrorQuery"]++
// 	}
// 	if errors.FormatError {
// 		errorCounters["FormatError"]++
// 	}
// 	if errors.ServerFailure {
// 		errorCounters["ServerFailure"]++
// 	}
// 	if errors.NXDOMAINError {
// 		errorCounters["NXDOMAINError"]++
// 	}
// 	if errors.NotImplemented {
// 		errorCounters["NotImplemented"]++
// 	}
// 	if errors.RefusedError {
// 		errorCounters["RefusedError"]++
// 	}
// 	if errors.YXDomainError {
// 		errorCounters["YXDomainError"]++
// 	}
// 	if errors.YXRRSetError {
// 		errorCounters["YXRRSetError"]++
// 	}
// 	if errors.NXRRSetError {
// 		errorCounters["NXRRSetError"]++
// 	}
// 	if errors.NotAuthorized {
// 		errorCounters["NotAuthorized"]++
// 	}
// 	if errors.NotInZone {
// 		errorCounters["NotInZone"]++
// 	}
// 	if errors.RootAuthOverride {
// 		errorCounters["RootAuthOverride"]++
// 	}
// 	if errors.NonRootAuthOverride {
// 		errorCounters["NonRootAuthOverride"]++
// 	}
// 	if errors.NoNsRecordFound {
// 		errorCounters["NoNsRecordFound"]++
// 	}
// 	if errors.NSNotGlueIP {
// 		errorCounters["NSNotGlueIP"]++
// 	}
// 	if errors.AuthOverrideWithGlueIP {
// 		errorCounters["AuthOverrideWithGlueIP"]++
// 	}
// 	if errors.RedirectToRoot {
// 		errorCounters["RedirectToRoot"]++
// 	}
// 	if errors.ResourceReuse {
// 		errorCounters["ResourceReuse"]++
// 	}
// 	if errors.NonRoutableIP {
// 		errorCounters["NonRoutableIP"]++
// 	}
// 	if errors.ANSintheSameAS {
// 		errorCounters["ANSintheSameAS"]++
// 	}
// 	if errors.ANSv4under24prefix {
// 		errorCounters["ANSv4under24prefix"]++
// 	}
// 	if errors.ANSv6under64prefix {
// 		errorCounters["ANSv6under64prefix"]++
// 	}
// 	if errors.ANSv6under48prefix {
// 		errorCounters["ANSv6under48prefix"]++
// 	}
// 	if errors.ANSintheSameCity {
// 		errorCounters["ANSintheSameCity"]++
// 	}
// 	if errors.ANSintheSameCountry {
// 		errorCounters["ANSintheSameCountry"]++
// 	}
// 	if errors.CircularDependencies {
// 		errorCounters["CircularDependencies"]++
// 	}
// }

func writeStatisticsToCSV(fileName string, mutex *sync.Mutex, errorCounters map[string]int) {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"ErrorType Count:"}
	writer.Write(header)

	for errorType, count := range errorCounters {
		row := []string{errorType, strconv.Itoa(count)}
		writer.Write(row)
	}
}
