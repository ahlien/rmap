package Resolver

import (
	"fmt"
	"hello/pkg/Cache"
	"hello/pkg/Graph"
	"hello/pkg/Identify"
	"net"
	"sync"
    "strings"
	"github.com/miekg/dns"
)

// Trace  类似于 dig +trace,把所有根都遍历一遍
func (d *Dig) Trace(domain string, queryType uint16, graph *Graph.DNSGraph, cache *Cache.DNSCache, mu *sync.Mutex,mod int) []string {

	// // 加锁输出
	// mu.Lock()
	// defer mu.Unlock()
	if d == nil || graph == nil || cache == nil {
		fmt.Printf("Error: one of the required arguments is nil\n")
		return nil
	}

	// 初始化一个空的字符串切片，用于存储 IP 地址
	ipAddresses := make([]string, 0)
	nodenum := graph.AddNode(domain, "begin", queryType, Graph.Begin)
	// 将开始节点的 level 设置为 0
	graph.SetNodeLevel(domain, "begin", queryType, 0)
	// 遍历所有根服务器
	// d.Resolver(domain, dns.TypeA, "8.8.8.8", graph, cache, &ipAddresses)
	for ip, ns := range rootZoneServers {
		// 在图中添加一个节点，表示当前的根服务器查询
		tempnodenum := graph.AddNode(domain, ip, queryType, Graph.Root)
		//fmt.Println(tempnodenum)

		graph.SetNodeNameServer(domain, ip, queryType, ns)
		graph.AddEdge(nodenum, tempnodenum, "begin to root server")
		graph.SetNodeZone(domain, ip, dns.TypeA, ".")


		//fmt.Println("所选取的根域名服务器sssssssssssssss：", ns, ip)
		// 解析域名，获取 IP 地址，并将结果存储在 ipAddresses 切片中
		d.Resolver(domain, dns.TypeA, ip, graph, cache, &ipAddresses)
		// 只选择一个根
		graph.SetNodeType(tempnodenum, Graph.Root)
		break
	}

	// if graph.HasSelfLoop(){
	// 	cache.SetError("OneCircularRef")
	// 	fmt.Println("sssss",graph.HasSelfLoop())
	// }
	// if graph.HasMultiNodeCycle(){
	// 	cache.SetError("MultiCircularRef")
	// 	fmt.Println("kkkkkk",graph.HasMultiNodeCycle())
	// }

	oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize:= graph.GetCycleStats()
	if oneNodeCycleCount!=0{
		cache.SetError("OneCircularRef")
	}
	if multiNodeCycleCount!=0{
		cache.SetError("MultiCircularRef")
	}
	if oneNodeCycleCount+multiNodeCycleCount!=0{
		cache.UpdateCacheWithCycleStats(oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize)
	}

    // num1,num2,num3,num4:=graph.GetCycleStats()
    // fmt.Println(domain,num1,num2,num3,num4)
	// graph.PrintCycles()
	// graph.PrintGraphDetails()
	// 返回去重后的 IP 地址列表

	switch mod {
	case 4:
		mu.Lock()
		// cache.PrintAuthoritativeNSIPs()
		// cache.GetNSRecords()
		// cache.GetCNameRecords()
		// fmt.Println(cache.GetCNameRecords())
		// num1,num2,num3,num4:=graph.GetCycleStats()
        // fmt.Println(num1,num2,num3,num4)
		cache.GetAnswerIPs()
		mu.Unlock()
	case 5:
		mu.Lock()
		cache.GetNSRecords()
		mu.Unlock()
	case 6:
		mu.Lock()
		cache.GetAAAARecords()
		mu.Unlock()
	case 7:
		mu.Lock()
		graph.PrintGraph()
		mu.Unlock()
	case 8:
		mu.Lock()
		cache.GetIPv6Nameservers()
		mu.Unlock()
	case 9:
		mu.Lock()
		graph.PrintCycles()
		mu.Unlock()
	default:
		// 如果需要，可以在这里处理默认情况
	}
	// sm:=cache.GetNSRecords()
	// fmt.Println(cache.GetNSRecords())
	// cache.PrintAuthoritativeNSIPs()
	
	// mu.Lock()
	// cache.GetDNAMERecords() 
	// mu.Unlock()
	return UniqueIPs(ipAddresses)
}

func IsMalformedDNSMsg(msg *dns.Msg) (bool, error) {
	// Check header fields (e.g., opcode, response code)
	if msg.Opcode > dns.OpcodeNotify {
		return true, fmt.Errorf("invalid opcode: %d", msg.Opcode)
	}
	if msg.Rcode > dns.RcodeBadCookie {
		return true, fmt.Errorf("invalid response code: %d", msg.Rcode)
	}

	// Check if there is at least one question if the question count is not zero
	if len(msg.Ns) == 0 {
		return true, fmt.Errorf("question section is nil, but Qdcount is %d")
	}

	// Additional checks can be implemented as needed
	// For instance, checking if sections match their count fields

	return false, nil
}

func (d *Dig) processDNSAnswerSection(msg *dns.Msg, server string,domain string, nodenum int, graph *Graph.DNSGraph, cache *Cache.DNSCache, GetIP *[]string) Cache.DNSMessage {
	nsMap := make(map[string]*Cache.NSRecord)
	var missingGlue []string
	allHaveGlue := true

	var ipList []net.IP
	seen := make(map[string]bool)
	
	for _, rr := range msg.Answer {
		// HasDuplicateRecords 判断 msg.Answer 中是否有完全相同的资源记录
		// 使用反射来生成资源记录的唯一字符串表示
		rrStr := fmt.Sprintf("%v", rr)
		if seen[rrStr] {
			cache.SetError("SameRRinAnswer")
			//fmt.Println(domain,rrStr)
		}
		seen[rrStr] = true

		switch rr := rr.(type) {
		// case 0:
		// 	// 识别数据包格式错误
		// 	cc.SetError("ERROR13")
	    case *dns.DNAME:
		    //收集所有 DNAME 记录
		    dname := rr.Target
		    cache.AddDnameRecord(dname)



		case *dns.SOA:
			// 识别 SOA
			cache.SetError("SOAInAnswerFound")
		case *dns.OPT:
			// 识别 OPT
			cache.SetError("OPTError")

		case *dns.A:
			ipList = append(ipList, rr.A)
			
			if ns, exists := nsMap[rr.Hdr.Name]; exists {
				ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, rr.A)
			} else {
				nsMap[rr.Hdr.Name] = &Cache.NSRecord{NameServer: rr.Hdr.Name, IPv4GlueIPs: []net.IP{rr.A}}
			}
			*GetIP = append(*GetIP, rr.A.To16().String())
			tempnodenum := graph.AddNode(domain, rr.A.String(), dns.TypeA, Graph.Common)
			//handleARecord(rr, domain, server, msgType, gg, cc, GetIP)
			graph.AddEdge(nodenum, tempnodenum, "get_A")
			if cache.Domain == domain {
				graph.AddNode(domain, rr.A.String(), dns.TypeA, Graph.LeaveA)


                d.Resolver(domain, dns.TypeAAAA,server, graph, cache, GetIP)

				cache.AddAnswerIP(rr.A.String())
				cache.SetError("SuccessfullyParsed")
			}
			// fmt.Println(rr.A)


		case *dns.AAAA:
			//搜集所有的 AAAA 类型资源记录
			cache.AddAAAARecord(rrStr)
			cache.AddIPv6Nameserver(rr.AAAA.String())
			ipList = append(ipList, rr.AAAA)
			if ns, exists := nsMap[rr.Hdr.Name]; exists {
				ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, rr.AAAA)
			} else {
				nsMap[rr.Hdr.Name] = &Cache.NSRecord{NameServer: rr.Hdr.Name, IPv6GlueIPs: []net.IP{rr.AAAA}}
			}
			//handleAAAARecord(rr, domain, server, msgType, gg, cc, GetIP)
			*GetIP = append(*GetIP, rr.AAAA.To16().String())
			tempnodenum := graph.AddNode(domain, rr.AAAA.String(), dns.TypeA, Graph.Common)
			graph.AddEdge(nodenum, tempnodenum, "get_AAAA")
			if cache.Domain == domain {
				graph.AddNode(domain, rr.AAAA.String(), dns.TypeA, Graph.LeaveAAAA)
				cache.AddAnswerIP(rr.AAAA.String())
				cache.SetError("SuccessfullyParsed")
			}
			// fmt.Println(rr.AAAA)

		case *dns.NS:
			if _, exists := nsMap[rr.Ns]; !exists {
				nsMap[rr.Ns] = &Cache.NSRecord{NameServer: rr.Ns}
				//allHaveGlue = false
			}
			tempnodenum := graph.AddNode(rr.Ns, "ns_begin", dns.TypeA, Graph.Begin)

			// fmt.Println(rr)



			// graph.SetNodeZone(rr.Ns, "ns_begin", dns.TypeA, rr.Header().Name)
			// graph.SetNodeNameServer(rr.Ns, "ns_begin", dns.TypeA, rr.Ns)
			
			
			
			
			graph.AddEdge(nodenum, tempnodenum, "")
			//tempnodenum := gg.AddNode(rr.Ns, "ns_begin", dns.TypeCNAME, Graph.LeaveCNAME)

		case *dns.CNAME:
			// If there is a CNAME type then no other type can exist and only one CNAME can exist for a domain name.
			// RFC1034

			if len(msg.Answer) > 1 {
				cache.SetError("NotOnlyOneCnameRR")
			}
			cache.AddCNameRecord(rr.Target)
			// fmt.Println(rr)

			// 判断 CNAME 解析依赖成环
			if cache.HasCNameCycle() {
				cache.SetError("CNAMECircularRef")
			}
			if rr.Target==domain{
				cache.SetError("CNAMECircularRef")
			}

			// //仅测试用
			// cache.AddNSRecord(rr.Target)







			tempnodenum := graph.AddNode(rr.Target, "cname_begin", dns.TypeCNAME, Graph.LeaveCNAME)
			// graph.SetNodeZone(rr.Target, "ns_begin", dns.TypeA, rr.Target)
			// graph.SetNodeNameServer(rr.Target, "ns_begin", dns.TypeA, rr.Target)
			graph.AddEdge(nodenum, tempnodenum, "")

			for ip, ns := range rootZoneServers {
				temptempnodenum := graph.AddNode(rr.Target, ip, dns.TypeA, Graph.Root)
				graph.SetNodeNameServer(rr.Target, ip, dns.TypeA, ns)
				//graph.AddEdge(nodenumCNAME, tempnodenum, "")
				graph.AddEdge(tempnodenum, temptempnodenum, "cname")
				//fmt.Println("CNAME:", rr.Target)
				// fmt.Println("CNAME:", ns,ip)
				graph.SetNodeZone(rr.Target, ip, dns.TypeA, ".")
				d.Resolver(rr.Target, dns.TypeA, ip, graph, cache, GetIP)
			}
			//fmt.Println(GetIP)

			//fmt.Println("CNAME",rr)
		    // 处理cname
			for _, ipStr := range UniqueIPs(*GetIP) {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					fmt.Printf("Invalid IP address: %s\n", ipStr)
						continue
				}
				//将之前的节点连起来
				//tempnodenum := gg.NodeNum(ns.NameServer, dns.TypeA, ip.String())
				//gg.AddNode(nodenum, tempnodenum)
				// if ip.To4() != nil {
				// 	// 是IPv4地址
				// 	ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, ip)
				// } else {
				// 	// 是IPv6地址
				// 	ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, ip)
				// }
					nodenum, _ := graph.GetNodeID(rr.Target, ip.String(), dns.TypeA)
					tempnodenum := graph.AddNode(domain, ip.String(), dns.TypeA, Graph.Common)
					graph.AddEdge(nodenum, tempnodenum, "cname")
					// fmt.Println("xxxxxxx:",domain,ip)
					d.Resolver(domain, dns.TypeA, ip.To16().String(), graph, cache, GetIP)
				}
			//d.handleCNAME(rr, domain, server, msgType, gg, cc, GetIP)
		}
	}
	// 检查IP列表 DNSAnswerSection 不检查
	// Identify.CheckIPList(ipList, cache)

	var nsRecords []Cache.NSRecord
	for _, ns := range nsMap {
		if len(ns.IPv4GlueIPs) == 0 && len(ns.IPv6GlueIPs) == 0 {
			missingGlue = append(missingGlue, ns.NameServer)
			allHaveGlue = false
		}
		nsRecords = append(nsRecords, *ns)
	}

	return Cache.DNSMessage{
		NSRecords:   nsRecords,
		MissingGlue: missingGlue,
		AllHaveGlue: allHaveGlue,
	}
}

func extractDNSMessage(domain string, msg *dns.Msg, nodenum int, cache *Cache.DNSCache, graph *Graph.DNSGraph) Cache.DNSMessage {
	if msg == nil || cache == nil || graph == nil {
		fmt.Printf("内存错误 ,Error: response or cache is nil in extractDNSMessage\n")
	}

	nsMap := make(map[string]*Cache.NSRecord)

	var ipList []net.IP
	seenadd := make(map[string]bool)
	// 收集所有的A和AAAA记录，并映射到对应的NS
	if len(msg.Extra) != 0 {
		for _, rr := range msg.Extra {
			// 判断 ADDIDITIOANAL 区域中是否有重复的资源记录
			rrStr := fmt.Sprintf("%v", rr)
			if seenadd[rrStr] {
				cache.SetError("SameRRinAddiditional")
				//fmt.Println(domain,rrStr)
			}
			seenadd[rrStr] = true
			switch rr := rr.(type) {
			case *dns.A:
				ipList = append(ipList, rr.A)
				if ns, exists := nsMap[rr.Hdr.Name]; exists {
					ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, rr.A)
				} else {
					nsMap[rr.Hdr.Name] = &Cache.NSRecord{NameServer: rr.Hdr.Name, IPv4GlueIPs: []net.IP{rr.A}}
				}
				tempnodenum := graph.AddNode(domain, rr.A.To16().String(), dns.TypeA, Graph.Common)
				graph.SetNodeNameServer(domain, rr.A.To16().String(), dns.TypeA, rr.Header().Name)

				graph.AddEdge(nodenum, tempnodenum, "")

			case *dns.AAAA:
				//搜集 AAAA 类型资源记录
				// fmt.Println(rrStr)
				cache.AddAAAARecord(rrStr)
				cache.AddIPv6Nameserver(rr.AAAA.String())
				ipList = append(ipList, rr.AAAA)

				if ns, exists := nsMap[rr.Hdr.Name]; exists {
					ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, rr.AAAA)
				} else {
					nsMap[rr.Hdr.Name] = &Cache.NSRecord{NameServer: rr.Hdr.Name, IPv6GlueIPs: []net.IP{rr.AAAA}}
				}
				tempnodenum := graph.AddNode(domain, rr.AAAA.To16().String(), dns.TypeA, Graph.Common)
				graph.SetNodeNameServer(domain, rr.AAAA.To16().String(), dns.TypeA, rr.Header().Name)
				graph.AddEdge(nodenum, tempnodenum, "")
			}
		}
		// 检查IP列表

		// Identify.CheckIPList(ipList, cache)
		
		// 判断是否是 tld 或 root server
		shouldSkipCheckIPList := false
		if len(msg.Ns)!=0{
			for _, nsrr := range msg.Ns {
				switch nsrr := nsrr.(type) {
				case *dns.NS:
					if nsrr.Header().Name != "" {
						dotCount := strings.Count(nsrr.Header().Name, ".")
						// fmt.Println(nsrr.Header().Name,dotCount)
						if dotCount <= 1 { // 0 dots for root server, 1 dot for tld
							shouldSkipCheckIPList = true
						}
					}
				}
				if shouldSkipCheckIPList{
					break
				}
			}
			if !shouldSkipCheckIPList {
				// 检查IP列表
				Identify.CheckIPList(ipList, cache)
			}
		}
		// Identify.CheckIPList(ipList, cache)
	}

	dnsMsg := Cache.DNSMessage{AllHaveGlue: true}
	seenauth := make(map[string]bool)

	// if len(msg.Ns) == 0 {
	// 	cache.SetError("NoNsRecordFound")
	// 	return dnsMsg
	// }
	for _, nsrr := range msg.Ns {
		// 判断 authority section 中是否有重复的资源记录
		// 使用反射来生成资源记录的唯一字符串表示
		rrStr := fmt.Sprintf("%v", nsrr)
		if seenauth[rrStr] {
			cache.SetError("SameRRinAuthority")
			//fmt.Println(domain,rrStr)
		}
		seenauth[rrStr] = true
		switch rr := nsrr.(type) {
		case *dns.DNAME:
			//收集所有 DNAME 记录
			dname := rr.Target
			cache.AddDnameRecord(dname)
		case *dns.NS:
			ns := rr
			//收集所有 NS 记录
			cache.AddNSRecord(ns.Ns)
			if record, exists := nsMap[ns.Ns]; exists {
				dnsMsg.NSRecords = append(dnsMsg.NSRecords, *record)
				// 设置节点的 Zone
				for _, ipv4 := range record.IPv4GlueIPs {
					graph.SetNodeZone(domain, ipv4.To16().String(), dns.TypeA, nsrr.Header().Name)
				}
				for _, ipv6 := range record.IPv6GlueIPs {
					graph.SetNodeZone(domain, ipv6.To16().String(), dns.TypeA, nsrr.Header().Name)
				}
				// 判断是否发生了越权授权的情形，且 glue 有对应的 IP 地址
				if extractTLD(ns.Header().Name) != extractTLD(ns.Ns) {
					if extractTLD(ns.Header().Name) != "" {
						cache.SetError("NonRootAuthOverride")
						cache.SetError("AuthOverrideWithGlueIP")
						//fmt.Println(ns)
					} else {
						cache.SetError("RootAuthOverride")
					}
				}
			} else {
				dnsMsg.NSRecords = append(dnsMsg.NSRecords, Cache.NSRecord{NameServer: ns.Ns})
				dnsMsg.MissingGlue = append(dnsMsg.MissingGlue, ns.Ns)
				dnsMsg.AllHaveGlue = false
				// fmt.Println(nsrr)
				// 判断是否发生了越权授权的情形，但未 glue 对应的 IP 地址
				if extractTLD(ns.Header().Name) != extractTLD(ns.Ns) {
					// cc.AddERROR27()
					cache.SetError("NonRootAuthOverride")
				} else {
					// example.com NS ns1.example.com，但未 glue IP 地址
					// https://community.akamai.com/customers/s/article/DNS-Circular-Detection-And-Looping?language=en_US
					cache.SetError("CircularDependencies")
				}
				//设置节点的 Zone
				tempnodenum := graph.AddNode(ns.Ns, "ns_begin", dns.TypeA, Graph.NsNotGlueIP)
				// graph.SetNodeNameServer(ns.Ns, "ns_begin", dns.TypeA, ns.Ns)
				// graph.SetNodeZone(ns.Ns, "ns_begin", dns.TypeA, ns.Header().Name)
				cache.SetError("NSNotGlueIP")
				cache.AddGluelessNSRecord(ns.Ns)
				graph.AddEdge(nodenum, tempnodenum, "")
			}
		case *dns.SOA:
			// cc.AddERROR10()
			cache.SetError("SOAInAuthority")
			graph.SetNodeType(nodenum, Graph.SOA)
		default:
			// Handle other types of resource records if needed
		}

		// 直接转向根域名服务器
		if string(nsrr.Header().Name) == "." {
			// cc.AddERROR30()
			cache.SetError("RedirectToRoot")

		}
	}
	return dnsMsg
}

func extractTLD(domain string) string {
	parts := dns.SplitDomainName(domain)
	if len(parts) < 2 {
		return ""
	}
	// Concatenate the last two parts and convert to lowercase
	tld := strings.ToLower(parts[len(parts)-2] + "." + parts[len(parts)-1])
	return tld
}

func Mapmerge(map1 map[string]string, map2 map[string]string) map[string]string {
	x := map1
	y := map2
	n := make(map[string]string)
	for i, v := range x {
		for j, w := range y {
			if i == j {
				n[i] = w

			} else {
				if _, ok := n[i]; !ok {
					n[i] = v
				}
				if _, ok := n[j]; !ok {
					n[j] = w
				}
			}
		}
	}
	return n
}

// UniqueIPs 返回一个新的字符串切片，其中只包含不重复的IP地址。
func UniqueIPs(ips []string) []string {
	uniqueSet := make(map[string]struct{}) // 使用map来去重
	var uniqueIPs []string

	for _, ip := range ips {
		if _, exists := uniqueSet[ip]; !exists {
			uniqueSet[ip] = struct{}{}
			uniqueIPs = append(uniqueIPs, ip)
		}
	}
	return uniqueIPs
}

func CheckIPRouting(server string, cc *Cache.DNSCache,domain string) bool {
	switch Identify.IsPrivateIP(server,cc) {
	case 0:
		cc.SetError("InvalidIP")
		return false
	case 4:
		cc.SetError("IPv4Reserved")
		return false
	case 6:
		cc.SetError("IPv6Reserved")
		return false
	default:
		// 可以添加一个默认的处理，如果需要的话
		// fmt.Println("No special handling needed")
	}
	return true
	//return fmt.Errorf("IP routing check failed")
}

func checkResponseRCode(rcode int, domain string, server string, cc *Cache.DNSCache, gg *Graph.DNSGraph) bool {
	nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
	switch rcode {
	case 0:
		// 	//fmt.Println("NOERROR")
		// 	cc.AddERROR0()
		//  1  FormErr
		//  2  Servfail
		//  3  NXDomain
		//  4  NotImp
		//  5  Refused
		//  6  YXDomain
		//  7  YXRRSet
		//  8  NXRRSet
		//  9  NotAuth
		//  10 NotZone
		return true
	case 1:
		//fmt.Println("出现错误  格式错误", domain)
		gg.SetNodeType(nodenum, Graph.FormErr)
		//fmt.Println(domain,server)
		cc.SetError("FormatError")
	case 2:
		//fmt.Println("出现错误  Server Failure", domain)
		gg.SetNodeType(nodenum, Graph.Serverfailure)
		cc.SetError("ServerFailure")
	case 3:
		//fmt.Println("出现错误  NXDOMAIN", domain)
		gg.SetNodeType(nodenum, Graph.NXDOMAIN)
		cc.SetError("NXDOMAIN")
	case 4:
		//fmt.Println("出现错误  不支持查询类型", domain)
		gg.SetNodeType(nodenum, Graph.NotImplemented)
		cc.SetError("NotImplemented")
		//fmt.Println(domain, server)
	case 5:
		//fmt.Println("出现错误  Refused", domain)
		gg.SetNodeType(nodenum, Graph.Refused)
		cc.SetError("Refused")

	case 6:
		gg.SetNodeType(nodenum, Graph.YXDomain)
		cc.SetError("YXDomain")

	case 7:
		gg.SetNodeType(nodenum, Graph.YXRRSet)
		cc.SetError("YXRRSet")

	case 8:
		gg.SetNodeType(nodenum, Graph.NXRRSet)
		cc.SetError("NXRRSet")

	case 9:
		gg.SetNodeType(nodenum, Graph.NotAuthorized)
		cc.SetError("NotAuth")

	case 10:
		gg.SetNodeType(nodenum, Graph.NotInZone)
		cc.SetError("NotZone")

	}
	return false
}

func handleCacheHit(domain string, server string, cc *Cache.DNSCache, gg *Graph.DNSGraph) error {
	// 先得到cache里的内容
	// value := cc.GetCache(domain, server, dns.TypeA)

	value := cc.GetIPsByDNSRecordKey(domain, server, dns.TypeA)

	// 得到主节点编号
	nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
	// 处理每个IP对应的节点
	//fmt.Println("缓存中取到的", value)
	for ns, ip := range value {
		tempnodenum := gg.AddNode(domain, ip, dns.TypeA, Graph.Common)
		gg.SetNodeNameServer(domain, ip, dns.TypeA, ns)
		gg.AddEdge(nodenum, tempnodenum, "")
		//打印 node num，DEBUUG 用
		// fmt.Println(nodenum, tempnodenum)
	}
	// 处理完成后返回
	return nil
}

// 处理数据包返回
func handlePacket(gg *Graph.DNSGraph, cc *Cache.DNSCache,status ExchangeStatus, domain string, msgType uint16, server string, Qtype uint16) bool {
	nodenum, _ := gg.GetNodeID(domain, server, Qtype)
	switch status {
	case Normal: //正常节点
		gg.SetNodeType(nodenum, Graph.Common)
		return true

	case Timeout:
		gg.SetNodeType(nodenum, Graph.Timeout)
		//fmt.Println(domain,server)
		// fmt.Println(cc.Domain,server)
		return false

	case TxIDMismatch:
		gg.SetNodeType(nodenum, Graph.IDMisMatch)
		return false
	}
	return true
}

// 处理 Recursion Available 的情况
func checkRecursionAvailable(cc *Cache.DNSCache, gg *Graph.DNSGraph, RecursionAvailableFlag bool, server string, domain string, Qtype uint16) error {
	if RecursionAvailableFlag {
		//fmt.Println("出现错误  Hijack", domain)
		nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
		gg.SetNodeType(nodenum, Graph.Hijack)
		//fmt.Println(domain,server)
		cc.SetError("RecursionAvailable")
	}
	return nil
}

// 检查 IP 是否有问题，并处理相关逻辑
func (d *Dig) checkIP(server string, domain string, msgType uint16, cc *Cache.DNSCache, gg *Graph.DNSGraph) bool {
	if err := d.SetDNS(server,cc.Version); err != nil {
		//fmt.Println("IP本身有问题", err)
		nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
		gg.SetNodeType(nodenum, Graph.IPerror)
		return false
	}
	return true
}

// 检查 IP 是否有问题，并处理相关逻辑
func checkIPNsRecords(NsNum int, server string, domain string, msgType uint16, cc *Cache.DNSCache, gg *Graph.DNSGraph) bool {
	nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
	if NsNum == 0 {
		gg.SetNodeType(nodenum, Graph.NoNsrecord)
		cc.SetError("NoNsRecordFound")
		return false
	}
	return true
}

func CheckResponseEDE(msg *dns.Msg, domain string, server string, cc *Cache.DNSCache, gg *Graph.DNSGraph) bool {
	// nodenum, _ := gg.GetNodeID(domain, server, dns.TypeA)
	hasEDE := false
	//fmt.Println(msg)
	if msg.Extra == nil {
		return hasEDE
	}
	for _, extra := range msg.Extra {
		if extra == nil {
			return hasEDE
		}
		//fmt.Println(extra)
		if opt, ok := extra.(*dns.OPT); ok {
			//fmt.Println("hahha=================================[[[[[[[[[[[[")
			if opt == nil {
				return hasEDE
			}
			if opt.Option == nil {
				//fmt.Println("xxxxxxxxxxxxxxxx", opt.Option)
				return hasEDE
			}

			for _, option := range opt.Option {
				//fmt.Println("xxxxxxxxxxxxxxxx")
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					//fmt.Printf("EDE code-------------------------\n")
					hasEDE = true
					// fmt.Printf("EDE code: %d, extra text: %s\n", ede.InfoCode, ede.ExtraText)
					switch ede.InfoCode {
					case 0: // Other
						cc.SetError("OtherError")
					case 1: // UnsupportedDNSKEYAlgorithm
						cc.SetError("UnsupportedDNSKEYAlgorithm")
					case 2: // UnsupportedDSDigestType
						cc.SetError("UnsupportedDSDigestType")
					case 3: // StaleAnswer
						cc.SetError("StaleAnswer")
					case 4: // ForgedAnswer
						cc.SetError("ForgedAnswer")
					case 5: // DNSSECIndeterminate
						cc.SetError("DNSSECIndeterminate")
					case 6: // DNSSECBogus
						cc.SetError("DNSSECBogus")
					case 7: // SignatureExpired
						cc.SetError("SignatureExpired")
					case 8: // SignatureNotYetValid
						cc.SetError("SignatureNotYetValid")
					case 9: // DNSKEYMissing
						cc.SetError("DNSKEYMissing")
					case 10: // RRSIGsMissing
						cc.SetError("RRSIGsMissing")
					case 11: // NoZoneKeyBitSet
						cc.SetError("NoZoneKeyBitSet")
					case 12: // NSECMissing
						cc.SetError("NSECMissing")
					case 13: // CachedError
						cc.SetError("CachedError")
					case 14: // NotReady
						cc.SetError("NotReady")
					case 15: // Blocked
						cc.SetError("Blocked")
					case 16: // Censored
						cc.SetError("Censored")
					case 17: // Filtered
						cc.SetError("Filtered")
					case 18: // Prohibited
						cc.SetError("Prohibited")
					case 19: // StaleNXDOMAINAnswer
						cc.SetError("StaleNXDOMAINAnswer")
					case 20: // NotAuthoritative
						cc.SetError("NotAuthoritative")
					case 21: // NotSupported
						cc.SetError("NotSupported")
					case 22: // NoReachableAuthority
						cc.SetError("NoReachableAuthority")
					case 23: // NetworkError
						cc.SetError("NetworkError")
					case 24: // InvalidData
						cc.SetError("InvalidData")
					default:
						fmt.Printf("Unknown EDE code: %d for domain: %s\n", ede.InfoCode, ede.ExtraText)
					}
				}
			}
		}
	}
	// // 确保 nodenum 有效并设置节点类型
	// if hasEDE && nodenum >= 0 {
	// 	gg.SetNodeType(nodenum, Graph.HasEDE)
	// }
	return hasEDE
}
