// DNS 报文的发送和接受
package Resolver

import (
	//"context"
	//"fmt"
	//"time"

	"net"
	"time"

	"github.com/miekg/dns"
)

type ExchangeStatus int

// 定义与 Status 相关的常量。
const (
	Normal       ExchangeStatus = iota // 正常状态
	Timeout                            // 超时状态
	TxIDMismatch                       // TXID不匹配
	Failure                            // 交互失败，但失败原因不是 Timeout
)

// 封装一下，方便调用 返回query msg
func NewMsg(Type uint16, domain string) *dns.Msg {
	return buildpack(Type, domain)
}

// func buildpack(Type uint16, domain string) *dns.Msg {
// 	domain = dns.Fqdn(domain)
// 	// Create a new DNS message
// 	msg := new(dns.Msg)
// 	//msg.SetQuestion(dns.Fqdn(domain), Type)
// 	msg.Id = dns.Id() //随机生成16bit的整数
// 	// //msg.Id = 4096
// 	msg.RecursionDesired = false
// 	msg.Question = make([]dns.Question, 1)
// 	msg.Question[0] = dns.Question{
// 		Name:   domain,
// 		Qtype:  Type,
// 		Qclass: dns.ClassINET,
// 	}
// 	// Enable EDNS0
// 	o := new(dns.OPT)
// 	o.Hdr.Name = "."
// 	o.Hdr.Rrtype = dns.TypeOPT
// 	msg.Extra = append(msg.Extra, o)

// 	return msg
// }

func buildpack(Type uint16, domain string) *dns.Msg {
	domain = dns.Fqdn(domain)
	msg := new(dns.Msg)
	msg.Id = dns.Id() //随机生成16bit的整数
	//msg.Id = 4096
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   domain,
		Qtype:  Type,
		Qclass: dns.ClassINET,
	}
	// // Enable EDNS0
	// o := new(dns.OPT)
	// o.Hdr.Name = "."
	// o.Hdr.Rrtype = dns.TypeOPT
	// msg.Extra = append(msg.Extra, o)

	msg.SetEdns0(4096, false) // 设置 UDP 数据包最大长度为 4096 字节   true和false表示是否支持DNSSEC

	return msg
}

// Exchange 发送msg 接收响应
func (d *Dig) Exchange(m *dns.Msg) (*dns.Msg, ExchangeStatus) {
	var msg *dns.Msg
	var status ExchangeStatus
	for i := 0; i < d.SetRetry(2); i++ {
		//fmt.Println(i)
		msg, status = d.exchange(m) //TODO返回一个空的context，todo 通常用在并不知道传递什么 context的情形
		if status != Normal {
			return msg, status
		}
		time.Sleep(time.Second / 10)
		// dns.Exchange()
	}
	return msg, Normal
}

func (d *Dig) exchange(m *dns.Msg) (*dns.Msg, ExchangeStatus) {
	client := &dns.Client{
		UDPSize: 4096,
		Timeout: d.readTimeout(),
		//DualStack :true,
	}
	// Send the DNS query
	// client := new(dns.Client)
	res, _, err := client.Exchange(m, d.RemoteAddr)
	if err != nil {
		//fmt.Println("Exchange error:", err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			//fmt.Println("Exchange error:", err)
			//fmt.Println(d.RemoteAddr)
			return nil, Timeout
		}
		return nil, Failure
	}
	if res.Id != m.Id {
		return res, TxIDMismatch
	}

	//fmt.Printf("DNS query time: %v\n", rtt)
	return res, Normal
}

// GetMsg 返回msg响应体
func (d *Dig) GetMsg(Type uint16, domain string) (*dns.Msg, ExchangeStatus) {
	m := buildpack(Type, domain)
	return d.Exchange(m)
}

// func queryDNS(domain, ip string, qtype uint16) (*dns.Msg, ExchangeStatus) {
// 	server := ip + ":53" // DNS 服务器地址

// 	// 创建一个新的 DNS 消息
// 	msg := new(dns.Msg)
// 	msg.SetQuestion(dns.Fqdn(domain), qtype)

// 	// 启用 EDNS0
// 	o := new(dns.OPT)
// 	o.Hdr.Name = "."
// 	o.Hdr.Rrtype = dns.TypeOPT
// 	msg.Extra = append(msg.Extra, o)

// 	// 发送 DNS 查询
// 	client := new(dns.Client)
// 	response, _, err := client.Exchange(msg, server)

// 	// if err != nil {
// 	// 	dns.ErrTime.Error()
// 	// 	if err == dns.ErrTruncated {
// 	// 		return response, TxIDMismatch
// 	// 	} else if err == dns.ErrTimeout {
// 	// 		return response, Timeout
// 	// 	} else {
// 	// 		return response, Failure
// 	// 	}
// 	// }

// 	return response, Normal
// }
