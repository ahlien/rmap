/*
 * Copyright 2025 ahlien from Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


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

// DNSRecordKey defines the structure for DNS record keys.
type DNSRecordKey struct {
	Domain string
	IP     string
	QType  uint16 // DNS query type, e.g., dns.TypeA, dns.TypeAAAA
}

// NSRecord stores nameserver information including IPv4 and IPv6 glue records.
type NSRecord struct {
	NameServer  string   // Nameserver domain name
	IPv4GlueIPs []net.IP // IPv4 glue records
	IPv6GlueIPs []net.IP // IPv6 glue records
}

// DNSMessage represents the structure of a DNS message.
type DNSMessage struct {
	NSRecords   []NSRecord
	MissingGlue []string // Stores NS names without corresponding glue records
	AllHaveGlue bool     // Indicates if all NS records have glue
}

// DNSCache defines the DNS cache structure.
type DNSCache struct {
	Domain             string
	CNamelink          []string
	Errors             ERROR
	Cycles             Cycle
	Records            map[DNSRecordKey][]NSRecord
	Version            int
	AuthoritativeNSIPs map[string]struct{}
	GluelessNSRecords  map[string]struct{}
	NSRecords          map[string]struct{}
	DnameRecords       map[string]struct{}
	AAAARecords        map[string]struct{}
	IPv6Nameservers    map[string]struct{}
	AnswerIP           map[string]struct{}
	mu                 sync.Mutex
}

// Cycle holds statistics about detected cycles in DNS resolution.
type Cycle struct {
	singleCycleNum int
	multiCycleNum  int
	maxCycle       int
	minCycle       int
}

// ERROR holds flags for different DNS errors and conditions.
type ERROR struct {
	SuccessfullyParsed bool
	TimeoutOccurred    bool
	RecursionAvailable bool

	SOAInAuthority    bool
	CNAMECircularRef  bool
	NsInAnswerFound   bool
	PacketFormatError bool
	SOAInAnswerFound  bool
	OPTError          bool
	MultiCircularRef  bool
	OneCircularRef    bool
	InvalidIP         bool
	IPv4Reserved      bool
	IPv6Reserved      bool

	// Other
	RootAuthOverride       bool
	NonRootAuthOverride    bool
	NoNsRecordFound        bool
	NSNotGlueIP            bool
	AuthOverrideWithGlueIP bool
	RedirectToRoot         bool
	ResourceReuse          bool
	NonRoutableIP          bool
	CircularDependencies   bool

	// Diminished server redundancy
	ANSintheSameAS     bool
	ANSv4under24prefix bool
	ANSv6under64prefix bool
	ANSv6under48prefix bool

	// RFC 1034
	NotOnlyOneCnameRR bool

	// RFC 2181
	SameRRinAnswer       bool
	SameRRinAuthority    bool
	SameRRinAddiditional bool

	// Extended DNS Errors (EDE Codes)
	OtherError                 bool
	UnsupportedDNSKEYAlgorithm bool
	UnsupportedDSDigestType    bool
	StaleAnswer                bool
	ForgedAnswer               bool
	DNSSECIndeterminate        bool
	DNSSECBogus                bool
	SignatureExpired           bool
	SignatureNotYetValid       bool
	DNSKEYMissing              bool
	RRSIGsMissing              bool
	NoZoneKeyBitSet            bool
	NSECMissing                bool
	CachedError                bool
	NotReady                   bool
	Blocked                    bool
	Censored                   bool
	Filtered                   bool
	Prohibited                 bool
	StaleNXDOMAINAnswer        bool
	NotAuthoritative           bool
	NotSupported               bool
	NoReachableAuthority       bool
	NetworkError               bool
	InvalidData                bool

	// DNS Response Codes (Rcode)
	NoError        bool
	FormatError    bool
	ServerFailure  bool
	NXDOMAIN       bool
	NotImplemented bool
	Refused        bool
	YXDomain       bool
	YXRRSet        bool
	NXRRSet        bool
	NotAuth        bool
	NotZone        bool
}

// SaveCacheToJSON writes the DNSCache to a JSON file.
func (dc *DNSCache) SaveCacheToJSON(storePath string) error {
	type SerializableCache struct {
		Domain    string
		CNamelink []string
		Errors    ERROR
		Records   map[string][]NSRecord
	}

	serializableCache := SerializableCache{
		Domain:    dc.Domain,
		CNamelink: dc.CNamelink,
		Errors:    dc.Errors,
		Records:   make(map[string][]NSRecord),
	}

	for key, value := range dc.Records {
		keyString := fmt.Sprintf("%s|%s|%d", key.Domain, key.IP, key.QType)
		serializableCache.Records[keyString] = value
	}

	jsonData, err := json.MarshalIndent(serializableCache, "", "  ")
	if err != nil {
		return err
	}

	domainName := strings.ReplaceAll(dc.Domain, ".", "_")
	fileName := fmt.Sprintf("%s_cache.json", domainName)
	filePath := filepath.Join(storePath, fileName)

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return err
	}

	fmt.Printf("Cache JSON data has been written to %s\n", filePath)
	return nil
}

// AddCNameRecord appends a new CNAME record if it is not a duplicate of the last entry.
func (dc *DNSCache) AddCNameRecord(cname string) {
	if len(dc.CNamelink) > 0 && dc.CNamelink[len(dc.CNamelink)-1] == cname {
		return
	}
	dc.CNamelink = append(dc.CNamelink, cname)
}

// HasCNameCycle checks whether CNamelink contains duplicates (CNAME loop).
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

// GetLastCNameRecord returns the last CNAME record in CNamelink.
func GetLastCNameRecord(cache DNSCache) (string, error) {
	if len(cache.CNamelink) == 0 {
		return "", errors.New("CNAME records not found")
	}
	return cache.CNamelink[len(cache.CNamelink)-1], nil
}

// GetIPsByDNSRecordKey retrieves IPv4 and IPv6 glue IPs by DNSRecordKey.
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

// AddNSRecord adds an NS record into DNSCache.
func (cache *DNSCache) AddNSRecord(name, server string) {
	if server == "199.9.14.201" {
		return
	}
	cache.NSRecords[name] = struct{}{}
}

// AddDnameRecord adds a DNAME record into DNSCache.
func (cache *DNSCache) AddDnameRecord(name string) {
	cache.DnameRecords[name] = struct{}{}
}

// AddGluelessNSRecord adds a glueless NS record into DNSCache.
func (cache *DNSCache) AddGluelessNSRecord(name string) {
	cache.GluelessNSRecords[name] = struct{}{}
}

// AddAAAARecord adds an AAAA record into DNSCache.
func (cache *DNSCache) AddAAAARecord(name string) {
	cache.AAAARecords[name] = struct{}{}
}

// AddIPv6Nameserver collects IPv6 nameservers.
func (cache *DNSCache) AddIPv6Nameserver(name string) {
	cache.IPv6Nameservers[name] = struct{}{}
}

// AddAnswerIP collects answer IPs.
func (cache *DNSCache) AddAnswerIP(name string) {
	cache.AnswerIP[name] = struct{}{}
}

// GetAnswerIPs prints all collected answer IPs.
func (cache *DNSCache) GetAnswerIPs() {
	if len(cache.AnswerIP) == 0 {
		return
	}

	answerIPs := make([]string, 0, len(cache.AnswerIP))
	for ip := range cache.AnswerIP {
		answerIPs = append(answerIPs, ip)
	}

	fmt.Println(cache.Domain, answerIPs)
}

// GetDNAMERecords prints all collected DNAME records.
func (cache *DNSCache) GetDNAMERecords() {
	if len(cache.DnameRecords) == 0 {
		return
	}
	dnameRecords := make([]string, 0, len(cache.DnameRecords))
	for name := range cache.DnameRecords {
		dnameRecords = append(dnameRecords, name)
	}
	fmt.Printf("Domain %v: {DNAMERecords: %v}\n", cache.Domain, dnameRecords)
}

// GetIPv6Nameservers prints all collected IPv6 nameservers.
func (cache *DNSCache) GetIPv6Nameservers() {
	if len(cache.IPv6Nameservers) == 0 {
		return
	}
	ipv6Nameservers := make([]string, 0, len(cache.IPv6Nameservers))
	for nameserver := range cache.IPv6Nameservers {
		ipv6Nameservers = append(ipv6Nameservers, nameserver)
	}
	fmt.Printf("Domain %v: {IPv6Nameservers: %v}\n", cache.Domain, strings.Join(ipv6Nameservers, ","))
}

// GetNSRecords prints all collected NS records.
func (cache *DNSCache) GetNSRecords() {
	nsRecords := make([]string, 0, len(cache.NSRecords))
	for name := range cache.NSRecords {
		nsRecords = append(nsRecords, name)
	}
	fmt.Printf("%s, {NSRecords: %v}\n", cache.Domain, nsRecords)
}

// GetCNameRecords returns all collected CNAME records.
func (cache *DNSCache) GetCNameRecords() []string {
	records := make([]string, 0, len(cache.CNamelink))
	for _, cname := range cache.CNamelink {
		records = append(records, cname)
	}
	return records
}

// GetAAAARecords prints all collected AAAA records.
func (cache *DNSCache) GetAAAARecords() {
	if len(cache.AAAARecords) == 0 {
		return
	}
	aaaaRecords := make([]string, 0, len(cache.AAAARecords))
	for cname := range cache.AAAARecords {
		aaaaRecords = append(aaaaRecords, cname)
	}
	fmt.Printf("Domain %v: {AAAARecords:\n%v}\n", cache.Domain, strings.Join(aaaaRecords, "\n"))
}

// NewDNSCache initializes a new DNSCache.
func NewDNSCache(domain string, version int) *DNSCache {
	return &DNSCache{
		Domain:             domain,
		Version:            version,
		CNamelink:          []string{},
		Records:            make(map[DNSRecordKey][]NSRecord),
		AuthoritativeNSIPs: make(map[string]struct{}),
		NSRecords:          make(map[string]struct{}),
		GluelessNSRecords:  make(map[string]struct{}),
		AAAARecords:        make(map[string]struct{}),
		IPv6Nameservers:    make(map[string]struct{}),
		AnswerIP:           make(map[string]struct{}),
	}
}

// AddAuthoritativeNSIP adds an authoritative NS IP into the cache.
func (cache *DNSCache) AddAuthoritativeNSIP(ip string) {
	cache.AuthoritativeNSIPs[ip] = struct{}{}
}

// PrintAuthoritativeNSIPs prints authoritative NS IPs filtered by version.
func (cache *DNSCache) PrintAuthoritativeNSIPs() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

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
			ips = append(ips, ip)
		}
	}

	fmt.Printf("%s: [%s]\n", cache.Domain, strings.Join(ips, ", "))
}

// AddRecord adds a record to DNSCache.
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

// GetRecords retrieves records from DNSCache by DNSRecordKey.
func (dc *DNSCache) GetRecords(key DNSRecordKey) ([]NSRecord, bool) {
	records, found := dc.Records[key]
	return records, found
}

// IsCacheHit checks if the given domain, IP, and query type are cached.
func (dc *DNSCache) IsCacheHit(domain string, ip string, qType uint16) bool {
	key := DNSRecordKey{
		Domain: domain,
		IP:     ip,
		QType:  qType,
	}
	_, found := dc.Records[key]
	return found
}

// PrintCache prints all information stored in the DNSCache.
func (dc *DNSCache) PrintCache() {
	fmt.Println("Cache Information:")
	fmt.Println("Domain:", dc.Domain)

	if len(dc.CNamelink) > 0 {
		fmt.Println("CNAME Records:")
		for _, cname := range dc.CNamelink {
			fmt.Println("  CNAME:", cname)
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

// UpdateCacheWithCycleStats updates cycle-related statistics.
func (dc *DNSCache) UpdateCacheWithCycleStats(oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize int) {
	dc.Cycles.singleCycleNum = oneNodeCycleCount
	dc.Cycles.multiCycleNum = multiNodeCycleCount
	dc.Cycles.maxCycle = maxCycleSize
	dc.Cycles.minCycle = minCycleSize
}

// SetError sets a given error flag to true if it exists in ERROR struct.
func (dc *DNSCache) SetError(errType string) {
	v := reflect.ValueOf(&dc.Errors).Elem()
	field := v.FieldByName(errType)
	if field.IsValid() && field.Kind() == reflect.Bool {
		field.SetBool(true)
	} else {
		fmt.Printf("Unknown or invalid error type: %s\n", errType)
	}
}
