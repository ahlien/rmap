/*If only one path of the domain is resolved successfully,
we assume that the domain can be resolved.
If all paths fail, we analyze the root cause of the error
*/

package Resolver

import (
	"fmt"
	"hello/pkg/Cache"
	"hello/pkg/Graph"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Dig dig
type Dig struct {
	Domain       string
	RemoteAddr   string
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	Protocol     string
	Retry        int
}

// Resolver
func (d *Dig) Resolver(domain string, msgType uint16, server string, graph *Graph.DNSGraph, cache *Cache.DNSCache, GetIP *[]string) ([]string, error) {
	// 循环递归推出条件
	// fmt.Println("haha",domain,server)
	// ipvetest:=net.ParseIP(server)
	// if ipvetest.To4() != nil {
	// 	// fmt.Println(server)
	// 	return nil,nil
	// } 
	// fmt.Println(server)
	cache.AddAuthoritativeNSIP(server)



	
	if exists := graph.IsNodeVisited(domain, server, msgType); exists {
		return nil, nil
	} else {
		graph.MarkNodeVisited(domain, server, msgType)
		//fmt.Println(domain, server)
	}

	// 判断 IP 地址是否有效
	if !d.checkIP(server, domain, msgType, cache, graph) {
		return nil, nil
	}
	//判断所配置的 IP 是否可路由
	if !CheckIPRouting(server, cache,domain) {
		// 处理错误
		return nil, nil
	}
	// fmt.Println("sss", cc.IsCacheHit(domain, server, dns.TypeA))
	if cache.IsCacheHit(domain, server, dns.TypeA) {
		handleCacheHit(domain, server, cache, graph)
		return nil, nil
	} else {
		msg, status := d.GetMsg(msgType, domain) //GetMsg
		// // 判断 EDE
		//fmt.Println(domain, server)
		//fmt.Println(msg)
		//fmt.Println("handlePacket:", handlePacket(gg, status, domain, msgType, server))

		if !handlePacket(graph,cache, status, domain, msgType, server, msgType) {
			return nil, nil
		}

		if msg==nil{
			// fmt.Println(cache.Domain,server)
			cache.SetError("TimeoutOccurred")
			return nil,nil
		}
		// // 判断是否是报文破裂，webcfs01.com 类型
		// malformed, _ := IsMalformedDNSMsg(msg)
		// if malformed {
		// 	fmt.Println(domain,server)
		// 	return nil,nil
		// } 
		if !checkResponseRCode(msg.Rcode, domain, server, cache, graph) {
			// 判断 EDE
			if len(msg.Answer) == 0 {
				CheckResponseEDE(msg, domain, server, cache, graph)
			}
			// 判断 RecursionAvailable 是否为 1
			checkRecursionAvailable(cache, graph, msg.MsgHdr.RecursionAvailable, server, domain, msgType)
			return nil, nil
		}
		// 判断 RecursionAvailable 是否为 1
		checkRecursionAvailable(cache, graph, msg.MsgHdr.RecursionAvailable, server, domain, msgType)

		parentNode, _ := graph.GetNodeID(domain, server, msgType)
		if len(msg.Answer) == 0 {
			// 判断报文中是否有 NS 类型的资源记录
			if !checkIPNsRecords(len(msg.Ns), server, domain, msgType, cache, graph) {
				return nil, nil
			}
			// 判断 EDE
			CheckResponseEDE(msg, domain, server, cache, graph)
			//fmt.Println(msg)
			package1 := extractDNSMessage(domain, msg, parentNode, cache, graph)

			//fmt.Println(package1)

			for _, ns := range package1.NSRecords {
				//var isGlueIP bool = true
				if len(ns.IPv4GlueIPs) == 0 && len(ns.IPv6GlueIPs) == 0 {
					//isGlueIP = false
					// 没有Glue记录，尝试从根域名服务器开始解析，得到对应的 IP 地址
					var ips []string
					nodenum, _ := graph.GetNodeID(ns.NameServer, "ns_begin", dns.TypeA)
					graph.AddEdge(parentNode, nodenum, "")
					//nodenum := gg.NodeNum(ns.NameServer, dns.TypeA, "")
					for ip, nameserver := range rootZoneServers {
						//nodenum, _ := Graph.NodeNum(domain, int(dns.TypeA), server)
						tempnodenum := graph.AddNode(ns.NameServer, ip, dns.TypeA, Graph.Root)
						graph.SetNodeNameServer(ns.NameServer, ip, dns.TypeA, nameserver)
						graph.AddEdge(nodenum, tempnodenum, "ns not glue IP")
						graph.SetNodeZone(domain, ip, dns.TypeA, ".")
						d.Resolver(ns.NameServer, dns.TypeA, ip, graph, cache, &ips)
					}

					// fmt.Println("des_ips", ips)
					for _, ipStr := range UniqueIPs(ips) {
						ip := net.ParseIP(ipStr)
						if ip == nil {
							fmt.Printf("Invalid IP address: %s\n", ipStr)
							continue
						}
						//将之前的节点连起来
						//tempnodenum := gg.NodeNum(ns.NameServer, dns.TypeA, ip.String())
						//gg.AddNode(nodenum, tempnodenum)
						if ip.To4() != nil {
							// 是IPv4地址
							ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, ip)
						} else {
							// 是IPv6地址
							ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, ip)
						}
						nodenum, _ := graph.GetNodeID(ns.NameServer, ip.String(), dns.TypeA)
						tempnodenum := graph.AddNode(domain, ip.String(), dns.TypeA, Graph.Common)
						graph.AddEdge(nodenum, tempnodenum, "ns_get_ip_and_begin_resolve")
					}
				}
				// resolver 函数
				for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
					// var nodetype uint16
					// if ip.To4() != nil {
					// 	nodetype = dns.TypeA
					// } else {
					// 	nodetype = dns.TypeAAAA
					// }
					// fmt.Println(ip)
					d.Resolver(domain, dns.TypeA, ip.To16().String(), graph, cache, GetIP)
				}
				//cc.Add(domain, server, dns.TypeA, tempvalue)
				cache.AddRecord(domain, server, dns.TypeA, package1.NSRecords)
			}
		} else {
			parentNode, _ := graph.GetNodeID(domain, server, msgType)
			package2 := d.processDNSAnswerSection(msg, server,domain, parentNode, graph, cache, GetIP)
			if !package2.AllHaveGlue {
				for _, ns := range package2.NSRecords {
					if len(ns.IPv4GlueIPs) == 0 && len(ns.IPv6GlueIPs) == 0 {
						// 没有Glue记录，尝试从根域名服务器开始解析，得到对应的 IP 地址
						// resolveNameServer(ns.NameServer)
						var ips []string
						nodenum, _ := graph.GetNodeID(ns.NameServer, "ns_begin", dns.TypeA)
						// graph.AddEdge(parentNode, nodenum, "NS not glue IP")
						//nodenum := gg.NodeNum(ns.NameServer, dns.TypeA, "")
						for ip, nameserver := range rootZoneServers {
							tempnodenum := graph.AddNode(ns.NameServer, ip, dns.TypeA, Graph.Root)
							//tempnodenum, _ := gg.GetNodeID(ns.NameServer, value, dns.TypeA)
							graph.AddEdge(nodenum, tempnodenum, "")
							//gg.AddNode(nodenum, tempnodenum)
							graph.SetNodeZone(domain, ip, dns.TypeA, ".")
							d.Resolver(ns.NameServer, dns.TypeA, ip, graph, cache, &ips)
							graph.SetNodeNameServer(ns.NameServer, ip, dns.TypeA, nameserver)
						}
						// 遍历IP地址列表
						for _, ipStr := range UniqueIPs(ips) {
							ip := net.ParseIP(ipStr)
							if ip == nil {
								fmt.Printf("Invalid IP address: %s\n", ipStr)
								continue
							}
							//将之前的节点连起来
							//tempnodenum := gg.NodeNum(ns.NameServer, dns.TypeA, ip.String())
							//gg.AddNode(nodenum, tempnodenum)
							if ip.To4() != nil {
								// 是IPv4地址
								ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, ip)
							} else {
								// 是IPv6地址
								ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, ip)
							}
						}

						// 先处理节点和边
						for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
							var nodetype uint16
							if ip.To4() != nil {
								nodetype = dns.TypeA
							} else {
								nodetype = dns.TypeAAAA
							}

							nodenum, _ := graph.GetNodeID(ns.NameServer, ip.String(), nodetype)
							tempnodenum := graph.AddNode(domain, ip.String(), nodetype, Graph.Common)
							graph.AddEdge(nodenum, tempnodenum, "")
						}

						// 再执行 resolver 函数
						for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
							//var nodetype uint16
							// if ip.To4() != nil {
							// 	nodetype = dns.TypeA
							// } else {
							// 	nodetype = dns.TypeAAAA
							// }
							d.Resolver(domain, dns.TypeA, ip.String(), graph, cache, GetIP)
						}
						cache.AddRecord(domain, server, dns.TypeA, package2.NSRecords)
					}

				}
			}
		}
	}
	return nil, nil
}
