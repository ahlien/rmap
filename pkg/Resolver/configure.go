// 包含 DNS 报文的构建，根域名服务器 IP 地址的存储等域名解析所必须具有的基本信息
package Resolver

import (
	//"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dnsTimeout time.Duration = 3 * time.Second
)

// Root zone ipv4/6 servers
// var root46servers = []string{
// 	"198.41.0.4",          //a发包发不过去
// 	"199.9.14.201",        //b
// 	"192.33.4.12",         //c
// 	"199.7.91.13",         //d
// 	"192.203.230.10",      //e
// 	"192.5.5.241",         //f
// 	"192.112.36.4",        //g
// 	"198.97.190.53",       //h
// 	"192.36.148.17",       //i
// 	"192.58.128.30",       //j
// 	"193.0.14.129",        //k
// 	"199.7.83.42",         //l
// 	"202.12.27.33",        //m
// 	"2001:503:ba3e::2:30", //a
// 	"2001:500:200::b",     //b
// 	"2001:500:2::c",       //c
// 	"2001:500:2d::d",      //d
// 	"2001:500:a8::e",      //e
// 	"2001:500:2f::f",      //f
// 	"2001:500:12::d0d",    //g
// 	"2001:500:1::53",      //h
// 	"2001:7fe::53",        //i
// 	"2001:503:c27::2:30",  //j
// 	"2001:7fd::1",         //k
// 	"2001:500:9f::42",     //l
// 	"2001:dc3::35"}        //m

// var rootZoneServers = map[string]string{
// 	"2001:503:ba3e::2:30": "b.root-servers.net"}
var rootZoneServers = map[string]string{
	// "199.9.14.201": "b.root-servers.net",
	"2001:500:200::b": "b.root-servers.net"}
// var rootZoneServers = map[string]string{
// 	// IPv4 addresses
// 	"198.41.0.4":     "a.root-servers.net",
// 	"199.9.14.201":   "b.root-servers.net",
// 	"192.33.4.12":    "c.root-servers.net",
// 	"199.7.91.13":    "d.root-servers.net",
// 	"192.203.230.10": "e.root-servers.net",
// 	"192.5.5.241":    "f.root-servers.net",
// 	"192.112.36.4":   "g.root-servers.net",
// 	"198.97.190.53":  "h.root-servers.net",
// 	"192.36.148.17":  "i.root-servers.net",
// 	"192.58.128.30":  "j.root-servers.net",
// 	"193.0.14.129":   "k.root-servers.net",
// 	"199.7.83.42":    "l.root-servers.net",
// 	"202.12.27.33":   "m.root-servers.net",
// 	// IPv6 addresses
// 	"2001:503:ba3e::2:30": "a.root-servers.net",
// 	"2001:500:200::b":     "b.root-servers.net",
// 	"2001:500:2::c":       "c.root-servers.net",
// 	"2001:500:2d::d":      "d.root-servers.net",
// 	"2001:500:a8::e":      "e.root-servers.net",
// 	"2001:500:2f::f":      "f.root-servers.net",
// 	"2001:500:12::d0d":    "g.root-servers.net",
// 	"2001:500:1::53":      "h.root-servers.net",
// 	"2001:7fe::53":        "i.root-servers.net",
// 	"2001:503:c27::2:30":  "j.root-servers.net",
// 	"2001:7fd::1":         "k.root-servers.net",
// 	"2001:500:9f::42":     "l.root-servers.net",
// 	"2001:dc3::35":        "m.root-servers.net",
// }

// 根域名 IPv4 和 IPv6 服务器列表
// var rootZoneServers = []string{
// 	// IPv4 地址
// 	"198.41.0.4",     // A
// 	"199.9.14.201",   // B
// 	"192.33.4.12",    // C
// 	"199.7.91.13",    // D
// 	"192.203.230.10", // E
// 	"192.5.5.241",    // F
// 	"192.112.36.4",   // G
// 	"198.97.190.53",  // H
// 	"192.36.148.17",  // I
// 	"192.58.128.30",  // J
// 	"193.0.14.129",   // K
// 	"199.7.83.42",    // L
// 	"202.12.27.33",   // M

// 	// IPv6 地址
// 	"2001:503:ba3e::2:30", // A
// 	"2001:500:200::b",     // B
// 	"2001:500:2::c",       // C
// 	"2001:500:2d::d",      // D
// 	"2001:500:a8::e",      // E
// 	"2001:500:2f::f",      // F
// 	"2001:500:12::d0d",    // G
// 	"2001:500:1::53",      // H
// 	"2001:7fe::53",        // I
// 	"2001:503:c27::2:30",  // J
// 	"2001:7fd::1",         // K
// 	"2001:500:9f::42",     // L
// 	"2001:dc3::35",        // M
// }

// isIPv4 检查给定的地址是否是 IPv4 地址
func isIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

// getFirstNAddresses 返回前 n 个 IPv4 或 IPv6 地址
func getFirstNAddresses(n int, useIPv4 bool) []string {
	var filteredServers []string

	// 根据地址类型过滤服务器
	for _, server := range rootZoneServers {
		if useIPv4 && isIPv4(server) {
			filteredServers = append(filteredServers, server)
		} else if !useIPv4 && !isIPv4(server) {
			filteredServers = append(filteredServers, server)
		}
	}

	// 返回前 n 个地址
	if n > len(filteredServers) {
		n = len(filteredServers)
	}
	return filteredServers[:n]
}

// SetTimeOut set read write dial timeout
func (d *Dig) SetTimeOut(t time.Duration) {
	d.ReadTimeout = t
	d.WriteTimeout = t
	d.DialTimeout = t
}

// SetDNS 设置查询的 DNS 服务器
func (d *Dig) SetDNS(host string, ipVersion int) error {
	var ip string
	port := "53"

	// 检查是否包含端口号
	if strings.Contains(host, ":") {
		// 尝试解析 IPv6 地址
		if strings.Count(host, ":") > 1 {
			if host[0] == '[' && host[len(host)-1] == ']' {
				// IPv6 地址，不带端口号
				ip = host[1 : len(host)-1]
			} else if strings.Contains(host, "]:") {
				// IPv6 地址，带端口号
				var err error
				ip, port, err = net.SplitHostPort(host)
				if err != nil {
					return err
				}
				ip = ip[1 : len(ip)-1]
			} else {
				// 纯 IPv6 地址，没有方括号
				ip = host
			}
		} else {
			// 解析 IPv4 地址，带端口号
			var err error
			ip, port, err = net.SplitHostPort(host)
			if err != nil {
				return err
			}
		}
	} else {
		// 纯 IP 地址，没有端口号
		ip = host
	}

	// 校验 IP 地址
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// 根据 ipVersion 选择设置 RemoteAddr
	switch ipVersion {
	case 4:
		// 只接受 IPv4
		if parsedIP.To4() == nil {
			return fmt.Errorf("provided address is not IPv4: %s", ip)
		}
		d.RemoteAddr = fmt.Sprintf("%s:%s", ip, port)
	case 6:
		// 只接受 IPv6
		if parsedIP.To4() != nil {
			return fmt.Errorf("provided address is not IPv6: %s", ip)
		}
		d.RemoteAddr = fmt.Sprintf("[%s]:%s", ip, port)
	default:
		// 接受 IPv4 和 IPv6
		if parsedIP.To4() != nil {
			// IPv4 地址
			d.RemoteAddr = fmt.Sprintf("%s:%s", ip, port)
		} else {
			// IPv6 地址
			d.RemoteAddr = fmt.Sprintf("[%s]:%s", ip, port)
		}
	}

	return nil
}

func (d *Dig) readTimeout() time.Duration {
	if d.ReadTimeout != 0 {
		return d.ReadTimeout
	}
	return dnsTimeout
}

// 可以设置一下发多少数据包，我们一般默认是1
func (d *Dig) SetRetry(k int) int {
	return k
}

func (d *Dig) RemoveDuplicates(nums []string) []string {
	uniqueMap := make(map[string]bool) // 使用 map 存储唯一的元素
	result := []string{}               // 用于存储去重后的结果
	for _, num := range nums {
		if !uniqueMap[num] {
			// 如果 map 中不存在当前元素，则将其添加到结果数组和 map 中
			uniqueMap[num] = true
			result = append(result, num)
		}
	}
	return result
}
