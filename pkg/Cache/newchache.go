package Cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

// DNSRecordKey 定义了DNS记录的键结构
type DNSRecordKey struct {
	Domain string
	IP     string
	QType  uint16 // DNS查询类型，如dns.TypeA, dns.TypeAAAA
}

// NSRecord 存储名称服务器信息，包括其IPv4和IPv6地址
type NSRecord struct {
	NameServer  string   // 名称服务器的域名
	IPv4GlueIPs []net.IP // Glue记录的IPv4地址列表
	IPv6GlueIPs []net.IP // Glue记录的IPv6地址列表
}

// DNS 报文的数据结构
type DNSMessage struct {
	NSRecords   []NSRecord
	MissingGlue []string // 存储没有对应Glue记录的NS名称
	AllHaveGlue bool     // 标记是否所有NS记录都有对应的Glue记录
}

// DNSCache 定义了DNS缓存结构
type DNSCache struct {
	Domain    string
	CNamelink []string
	Errors    ERROR
	Cycles    Cycle
	Records   map[DNSRecordKey][]NSRecord
	// Cname     map[DNSRecordKey]string
	Version   int

	// 使用 map 作为集合来存储不同的权威域名服务器IP
    AuthoritativeNSIPs map[string]struct{}
	mu        sync.Mutex // 用于同步的互斥锁
	GluelessNSRecords         map[string]struct{} // 存储不同的 GluelessNS 记录
	NSRecords          map[string]struct{} // 存储不同的 NS 记录
	DnameRecords          map[string]struct{} // 存储不同的 DNAME 记录
	AAAARecords          map[string]struct{} // 存储不同的 AAAA 记录
	IPv6Nameservers    map[string]struct{} // 存储不同的 IPv6 Nameserver
	AnswerIP           map[string]struct{} // 存储结果
}

type Cycle struct{
	singleCycleNum int
	multiCycleNum  int
	maxCycle int
	minCycle int
}

// ERROR 结构体表示DNS解析过程中可能发生的各种错误和状态信息。
type ERROR struct {
	SuccessfullyParsed bool // 能够成功解析
	TimeoutOccurred    bool // 发生超时，lamedelegation
	RecursionAvailable bool // RA=1,可能指向递归解析器

	SOAInAuthority    bool // SOA 在 Authority区域
	CNAMECircularRef  bool // CNAME循环引用
	NsInAnswerFound   bool // 在 answer 区域中找到 NS 记录
	PacketFormatError bool // 数据包格式错误
	SOAInAnswerFound  bool // 在答案中找到SOA记录
	OPTError          bool // OPT记录错误
	MultiCircularRef  bool // 多元环
	OneCircularRef    bool // 一元环
	InvalidIP         bool // 无效IP地址
	IPv4Reserved      bool // IPv4保留地址
	IPv6Reserved      bool // IPv6保留地址

	// Other
	RootAuthOverride       bool // 根越权授权
	NonRootAuthOverride    bool // 非根越权授权
	NoNsRecordFound        bool // 未找到NS记录
	NSNotGlueIP            bool // NS 记录没有 Glue IP
	AuthOverrideWithGlueIP bool // 越权授权并带有粘合IP
	RedirectToRoot         bool // 重定向到根
	ResourceReuse          bool // 资源复用
	NonRoutableIP          bool // IP地址不可路由
	CircularDependencies   bool // example.com NS ns1.example.com，但未 glue IP 地址

	// diminished server redundancy
	ANSintheSameAS      bool // 权威域名服务器位于同一个 AS
	ANSv4under24prefix  bool // 权威域名服务器位于同一个 /24 前缀下
	ANSv6under64prefix  bool // 权威域名服务器位于同一个 /64 前缀下
	ANSv6under48prefix  bool // 权威域名服务器位于同一个 /48 前缀下

	// RFC 1034
	NotOnlyOneCnameRR bool // RFC1034 If there is a CNAME type then no other type can exist and only one CNAME can exist for a domain name

	// RFC2181
	SameRRinAnswer       bool // RFC2181 All records should be unique (there should be no duplicates).
	SameRRinAuthority    bool // RFC2181 All records should be unique (there should be no duplicates).
	SameRRinAddiditional bool // RFC2181 All records should be unique (there should be no duplicates).

	// EDE (Extended DNS Error) Codes
	OtherError                 bool // 0 - Other Error
	UnsupportedDNSKEYAlgorithm bool // 1 - Unsupported DNSKEY Algorithm
	UnsupportedDSDigestType    bool // 2 - Unsupported DS Digest Type
	StaleAnswer                bool // 3 - Stale Answer
	ForgedAnswer               bool // 4 - Forged Answer
	DNSSECIndeterminate        bool // 5 - DNSSEC Indeterminate
	DNSSECBogus                bool // 6 - DNSSEC Bogus
	SignatureExpired           bool // 7 - Signature Expired
	SignatureNotYetValid       bool // 8 - Signature Not Yet Valid
	DNSKEYMissing              bool // 9 - DNSKEY Missing
	RRSIGsMissing              bool // 10 - RRSIGs Missing
	NoZoneKeyBitSet            bool // 11 - No Zone Key Bit Set
	NSECMissing                bool // 12 - NSEC Missing
	CachedError                bool // 13 - Cached Error
	NotReady                   bool // 14 - Not Ready
	Blocked                    bool // 15 - Blocked
	Censored                   bool // 16 - Censored
	Filtered                   bool // 17 - Filtered
	Prohibited                 bool // 18 - Prohibited
	StaleNXDOMAINAnswer        bool // 19 - Stale NXDOMAIN Answer
	NotAuthoritative           bool // 20 - Not Authoritative
	NotSupported               bool // 21 - Not Supported
	NoReachableAuthority       bool // 22 - No Reachable Authority
	NetworkError               bool // 23 - Network Error
	InvalidData                bool // 24 - Invalid Data

	// DNS Response Codes (Rcode)
	NoError        bool // 没有错误
	FormatError    bool // 格式错误
	ServerFailure  bool // 服务器失败
	NXDOMAIN       bool // 名称错误
	NotImplemented bool // 未实现
	Refused        bool // 拒绝
	YXDomain       bool // 域存在
	YXRRSet        bool // RR集存在
	NXRRSet        bool // RR集不存在
	NotAuth        bool // 非授权
	NotZone        bool // 非区域
	// BadVersOrSig   bool // 错误版本或签名
	// BadKey         bool // 错误密钥
	// BadTime        bool // 时间错误
	// BadMode        bool // 模式错误
	// BadName        bool // 名称错误
	// BadAlg         bool // 算法错误
	// BadTrunc       bool // 截断错误
	// BadCookie      bool // Cookie错误
}



// EDE 常量
const (
	OtherError                 = 0  // 0 - Other Error
	UnsupportedDNSKEYAlgorithm = 1  // 1 - Unsupported DNSKEY Algorithm
	UnsupportedDSDigestType    = 2  // 2 - Unsupported DS Digest Type
	StaleAnswer                = 3  // 3 - Stale Answer
	ForgedAnswer               = 4  // 4 - Forged Answer
	DNSSECIndeterminate        = 5  // 5 - DNSSEC Indeterminate
	DNSSECBogus                = 6  // 6 - DNSSEC Bogus
	SignatureExpired           = 7  // 7 - Signature Expired
	SignatureNotYetValid       = 8  // 8 - Signature Not Yet Valid
	DNSKEYMissing              = 9  // 9 - DNSKEY Missing
	RRSIGsMissing              = 10 // 10 - RRSIGs Missing
	NoZoneKeyBitSet            = 11 // 11 - No Zone Key Bit Set
	NSECMissing                = 12 // 12 - NSEC Missing
	CachedError                = 13 // 13 - Cached Error
	NotReady                   = 14 // 14 - Not Ready
	Blocked                    = 15 // 15 - Blocked
	Censored                   = 16 // 16 - Censored
	Filtered                   = 17 // 17 - Filtered
	Prohibited                 = 18 // 18 - Prohibited
	StaleNXDOMAINAnswer        = 19 // 19 - Stale NXDOMAIN Answer
	NotAuthoritative           = 20 // 20 - Not Authoritative
	NotSupported               = 21 // 21 - Not Supported
	NoReachableAuthority       = 22 // 22 - No Reachable Authority
	NetworkError               = 23 // 23 - Network Error
	InvalidData                = 24 // 24 - Invalid Data
)

// SaveCacheToJSON 将DNSCache写入JSON文件
func (dc *DNSCache) SaveCacheToJSON(storePath string) error {
	// 创建一个可以序列化的结构体
	type SerializableCache struct {
		Domain    string
		CNamelink []string
		Errors    ERROR
		Records   map[string][]NSRecord
	}

	// 创建一个可序列化的缓存副本
	serializableCache := SerializableCache{
		Domain:    dc.Domain,
		CNamelink: dc.CNamelink,
		Errors:    dc.Errors,
		Records:   make(map[string][]NSRecord),
	}

	// 将DNSRecordKey转换为字符串
	for key, value := range dc.Records {
		keyString := fmt.Sprintf("%s|%s|%d", key.Domain, key.IP, key.QType)
		serializableCache.Records[keyString] = value
	}

	// 将结构体转换为JSON
	jsonData, err := json.MarshalIndent(serializableCache, "", "  ")
	if err != nil {
		return err
	}

	// 创建文件名
	domainName := strings.ReplaceAll(dc.Domain, ".", "_")
	fileName := fmt.Sprintf("%s_cache.json", domainName)
	filePath := filepath.Join(storePath, fileName)

	
	// 创建并写入文件
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("hahahha:Cache JSON data has been written to %s\n", filePath)
	return nil
}

// AddCNameRecord 向 DNS 缓存中添加 CNAME 记录
func (dc *DNSCache) AddCNameRecord(cname string) {
	// key := DNSRecordKey{
	// 	Domain: domain,
	// 	IP:     ip,
	// 	QType:  qType,
	// }
	//dc.Cname[key] = cname

	if len(dc.CNamelink) > 0 && dc.CNamelink[len(dc.CNamelink)-1] == cname {
		// 如果相同，则不插入
		return
	}
	dc.CNamelink = append(dc.CNamelink, cname)
}

// HasCNameCycle 检查 CNamelink 中是否有重复元素，即是否会形成 CNAME 环
func (dc *DNSCache) HasCNameCycle() bool {
	seen := make(map[string]bool)
	for _, cname := range dc.CNamelink {
		if seen[cname] {
			return true
		}
		seen[cname] = true
	}
	return false
}

// GetLastCNameRecord 获取CNAME记录数组中的最后一个记录
func GetLastCNameRecord(cache DNSCache) (string, error) {
	cnameCount := len(cache.CNamelink)
	if cnameCount == 0 {
		return "", errors.New("CNAME records not found")
	}

	lastCName := cache.CNamelink[cnameCount-1]
	return lastCName, nil
}

// GetIPsByDNSRecordKey 根据DNSRecordKey获取所有IPv4和IPv6地址的集合，返回值为map[ip]nameserver
func (dc *DNSCache) GetIPsByDNSRecordKey(domain string, ip string, qType uint16) map[string]string {
	ipToNameServer := make(map[string]string)

	key := DNSRecordKey{
		Domain: domain,
		IP:     ip,
		QType:  qType,
	}

	records, found := dc.Records[key]
	if !found {
		return ipToNameServer
	}

	for _, record := range records {
		for _, ipv4 := range record.IPv4GlueIPs {
			ipToNameServer[ipv4.String()] = record.NameServer
		}
		for _, ipv6 := range record.IPv6GlueIPs {
			ipToNameServer[ipv6.String()] = record.NameServer
		}
	}

	return ipToNameServer
}


// AddNSRecord 向 DNSCache 中添加一个新的 NS 记录
func (cache *DNSCache) AddNSRecord(name string) {
	cache.NSRecords[name] = struct{}{}
}


// AddNSRecord 向 DNSCache 中添加一个新的 NS 记录
func (cache *DNSCache) AddDnameRecord(name string) {
	cache.DnameRecords[name] = struct{}{}
}


// AddNSRecord 向 DNSCache 中添加一个新的 NS 记录
func (cache *DNSCache) AddGluelessNSRecord(name string) {
	cache.GluelessNSRecords[name] = struct{}{}
}

// AddAAAARecord 向 DNSCache 中添加一个新的 AAAA 记录
func (cache *DNSCache) AddAAAARecord(name string) {
	cache.AAAARecords[name] = struct{}{}
}


// 收集所有 IPv6 服务器
func (cache *DNSCache) AddIPv6Nameserver(name string) {
	cache.IPv6Nameservers[name] = struct{}{}
}

// 收集所有的 Answer IP
func (cache *DNSCache) AddAnswerIP(name string) {
	cache.AnswerIP[name] = struct{}{}
}


// GetAnswerIPs 返回所有的 Answer IP 地址作为数组
func (cache *DNSCache) GetAnswerIPs() {
    // 如果 AnswerIP 为空，返回一个空数组
    if len(cache.AnswerIP) == 0 {
        return 
    }

    // 创建一个切片来存储 IP 地址
    answerIPs := make([]string, 0, len(cache.AnswerIP))
    
    // 遍历 AnswerIP map，将所有的 IP 地址添加到切片中
    for ip := range cache.AnswerIP {
        answerIPs = append(answerIPs, ip)
    }

	fmt.Println(cache.Domain,answerIPs)
    return 
}



// GetNSRecords 获取所有的 DNAME 记录并直接打印
func (cache *DNSCache) GetDNAMERecords() {
	if len(cache.DnameRecords) == 0 {
        // Return immediately if there are no DNAME records
        return
    }
    dnameRecords := make([]string, 0, len(cache.DnameRecords))
    for name := range cache.DnameRecords {
        dnameRecords = append(dnameRecords, name)
    }

    // 直接打印格式化的输出
	fmt.Printf("Domain  %v: {dnameRecords: %v}\n", cache.Domain,dnameRecords)
}





// GetIPv6Nameservers 获取所有的 IPv6 Nameservers 并直接打印
func (cache *DNSCache) GetIPv6Nameservers() {
	if len(cache.IPv6Nameservers) == 0 {
		// 如果没有 IPv6 Nameservers，直接返回
		return
	}
	ipv6Nameservers := make([]string, 0, len(cache.IPv6Nameservers))
	for nameserver := range cache.IPv6Nameservers {
		ipv6Nameservers = append(ipv6Nameservers, nameserver)
	}

	// 使用换行符分隔记录并打印格式化的输出
	fmt.Printf("Domain %v: {IPv6Nameservers:%v}\n", cache.Domain, strings.Join(ipv6Nameservers, ","))
}






// GetNSRecords 获取所有的 NS 记录和 Glueless NS 记录，并直接打印
func (cache *DNSCache) GetNSRecords() {
    nsRecords := make([]string, 0, len(cache.NSRecords))
    for name := range cache.NSRecords {
        nsRecords = append(nsRecords, name)
    }

    gluelessNSRecords := make([]string, 0, len(cache.GluelessNSRecords))
    for name := range cache.GluelessNSRecords {
        gluelessNSRecords = append(gluelessNSRecords, name)
    }

    // 直接打印格式化的输出
	fmt.Printf("{NSRecords: %v, GluelessNSRecords: %v}\n",nsRecords, gluelessNSRecords)
}


// GetNSRecords 获取所有的 NS 记录，并返回一个可以直接使用 fmt.Println 打印的数组
func (cache *DNSCache) GetCNameRecords() []string {
	records := make([]string, 0, len(cache.NSRecords))
	for _, cname := range cache.CNamelink {
		records = append(records, cname)
	}
	//sort.Strings(records) // 对记录进行排序
	return records
}


// GetAAAARecords 获取所有的 AAAA 记录并直接打印
func (cache *DNSCache) GetAAAARecords() {
	if len(cache.AAAARecords) == 0 {
		// 如果没有 AAAA 记录，直接返回
		return
	}
	aaaaRecords := make([]string, 0, len(cache.AAAARecords))
	for cname := range cache.AAAARecords {
		aaaaRecords = append(aaaaRecords, cname)
	}

	// 使用换行符分隔记录并打印格式化的输出
	fmt.Printf("Domain %v: {aaaaRecords:\n%v}\n", cache.Domain, strings.Join(aaaaRecords, "\n"))
}

// // GetNSRecords 获取所有的 NS 记录
// func (cache *DNSCache) GetCNameRecords() []string {
// 	var records []string
// 	for _, cname := range cache.CNamelink {
// 		records = append(records, cname)
// 	}
// 	return records
// }

// NewDNSCache 是一个用于初始化 DNSCache 的函数
func NewDNSCache(domain string, version int) *DNSCache {
    return &DNSCache{
        Domain:            domain,
		Version:           version,
        CNamelink:         []string{},
        Records:           make(map[DNSRecordKey][]NSRecord),
        AuthoritativeNSIPs: make(map[string]struct{}),
		NSRecords:         make(map[string]struct{}),
		GluelessNSRecords: make(map[string]struct{}),
		AAAARecords:  make(map[string]struct{}),
		IPv6Nameservers:  make(map[string]struct{}),
		AnswerIP:  make(map[string]struct{}),
    }
}


// AddAuthoritativeNSIP 添加一个权威域名服务器IP到集合中
func (cache *DNSCache) AddAuthoritativeNSIP(ip string) {
    cache.AuthoritativeNSIPs[ip] = struct{}{}
}

// PrintAuthoritativeNSIPs 打印所有权威域名服务器IP
func (cache *DNSCache) PrintAuthoritativeNSIPs() {
	cache.mu.Lock() // 获取锁
	defer cache.mu.Unlock() // 在函数结束时释放锁

	var ips []string
	for ip := range cache.AuthoritativeNSIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		switch cache.Version {
		case 4:
			if parsedIP.To4() != nil {
				ips = append(ips, ip)
			}
		case 6:
			if parsedIP.To16() != nil && parsedIP.To4() == nil {
				ips = append(ips, ip)
			}
		default:
			// 如果版本不是 4 或 6，则不进行过滤，直接添加所有 IP
			ips = append(ips, ip)
		}
	}

	// 输出格式: 域名: [IP1, IP2, ...], SuccessfullyParsed: true/false
	fmt.Printf("%s: [%s], answer: %v\n", cache.Domain, strings.Join(ips, ", "))
}
// AddRecord 向DNS缓存中添加记录
func (dc *DNSCache) AddRecord(domain string, ip string, qType uint16, record []NSRecord) {
	key := DNSRecordKey{
		Domain: domain,
		IP:     ip,
		QType:  qType,
	}

	if dc.Records == nil {
		dc.Records = make(map[DNSRecordKey][]NSRecord)
	}

	dc.Records[key] = record
}

// GetRecords 从DNS缓存中获取记录
func (dc *DNSCache) GetRecords(key DNSRecordKey) ([]NSRecord, bool) {
	records, found := dc.Records[key]
	return records, found
}

// IsCacheHit 判断给定的域名、IP地址和查询类型是否命中缓存
func (dc *DNSCache) IsCacheHit(domain string, ip string, qType uint16) bool {
	key := DNSRecordKey{
		Domain: domain,
		IP:     ip,
		QType:  qType,
	}

	_, found := dc.Records[key]
	return found
}

// PrintCache 打印缓存中的所有信息
func (dc *DNSCache) PrintCache() {
	fmt.Println("Cache Information:")
	fmt.Println("Domain:", dc.Domain)

	if len(dc.CNamelink) > 0 {
		fmt.Println("CName Records:")
		for _, cname := range dc.CNamelink {
			fmt.Println("  CName:", cname)
		}
	}

	for key, records := range dc.Records {
		fmt.Println("Key:")
		fmt.Println("  Domain:", key.Domain)
		fmt.Println("  IP:", key.IP)
		fmt.Println("  QType:", key.QType)

		fmt.Println("Records:")
		for _, record := range records {
			fmt.Println("  IPv4GlueIPs:", record.IPv4GlueIPs)
			fmt.Println("  IPv6GlueIPs:", record.IPv6GlueIPs)
		}
	}
}

func (dc *DNSCache)  UpdateCacheWithCycleStats(oneNodeCycleCount,multiNodeCycleCount,maxCycleSize,minCycleSize int) {
	dc.Cycles.singleCycleNum = oneNodeCycleCount
	dc.Cycles.multiCycleNum = multiNodeCycleCount
	dc.Cycles.maxCycle = maxCycleSize
	dc.Cycles.minCycle = minCycleSize
}


// SetError 设置指定错误类型的标记为true
func (dc *DNSCache) SetError(errType string) {
	v := reflect.ValueOf(&dc.Errors).Elem()
	field := v.FieldByName(errType)
	if field.IsValid() && field.Kind() == reflect.Bool {
		field.SetBool(true)
	} else {
		fmt.Printf("Unknown or invalid error type: %s\n", errType)
	}
}
