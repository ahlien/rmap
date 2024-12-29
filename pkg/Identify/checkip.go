// 用于识别 ns glue 的 IP 地址是否可路由
package Identify

import (
	"fmt"
	"hello/pkg/Cache"
	"net"
	"strings"
	"log"

	"github.com/oschwald/geoip2-golang"
)

// IPInfo 包含 IP 地址的地理位置、ASN 信息和前缀信息
type IPInfo struct {
	CountryCode      string
	City             string
	ASN              uint
	IPPrefix24       string
	IPPrefix64       string
	IPPrefix48       string
	AutonomousSystem string
}

// refer to: https://en.wikipedia.org/wiki/Reserved_IP_addresses
// 返回 0 表示 ipString 不是一个有效的IP地址
// 返回 4 表示 ipString 是一个 IPv4 reserved IP
// 返回 6 表示 ipString 是一个 IPv6 reserved IP
// 返回 1 表示 为可路由的 IP
func IsPrivateIP(ipString string,cc *Cache.DNSCache) int {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return 0
	}
	reservedIPv4 := []net.IPNet{
		{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 0, 0, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(192, 88, 99, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)},
		{IP: net.IPv4(198, 51, 100, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(224, 0, 0, 0), Mask: net.CIDRMask(4, 32)},
		{IP: net.IPv4(233, 252, 0, 0), Mask: net.CIDRMask(24, 32)},
		{IP: net.IPv4(240, 0, 0, 0), Mask: net.CIDRMask(4, 32)},
		{IP: net.IPv4(255, 255, 255, 255), Mask: net.CIDRMask(32, 32)},
	}

	// IPv6 reserved IP
	reservedIPv6 := []net.IPNet{
		{IP: net.ParseIP("::"), Mask: net.CIDRMask(128, 128)},
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		{IP: net.ParseIP("::ffff:0.0.0.0"), Mask: net.CIDRMask(96, 128)},
		{IP: net.ParseIP("::ffff:0:0:0"), Mask: net.CIDRMask(96, 128)},
		{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)},
		{IP: net.ParseIP("64:ff9b:1::"), Mask: net.CIDRMask(48, 128)},
		{IP: net.ParseIP("100::"), Mask: net.CIDRMask(64, 128)},
		{IP: net.ParseIP("2001:20::"), Mask: net.CIDRMask(28, 128)},
		{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
		{IP: net.ParseIP("2002::"), Mask: net.CIDRMask(16, 128)},
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
		{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)},
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(64, 128)},
	}

	// // Map of reserved IPs to their purposes
	// ipPurposeMap := map[int]string{
	// 	0:      "Loopback Address",
	// 	1:       "Unspecified Address",
	// 	2: "IPv4-mapped Address",
	// 	3: "IPv4-IPv6 Translation",
	// 	4:     "Discard-Only Address Block",
	// 	5:    "IETF Protocol Assignments",
	// 	6:  "Benchmarking",
	// 	7: "Documentation",
	// 	8: "ORCHID",
	// 	9:    "6to4",
	// 	10:     "Unique-Local",
	// 	11 :    "Link-Scoped Unicast",
	// }

	if strings.Contains(ipString, ":") {
		for _, network := range reservedIPv6 {
			if network.Contains(ip) {
				// println(cc.Domain,ipString, ipPurposeMap[index])
				return 6
			}
		}
	} else {
		for _, network := range reservedIPv4 {
			if network.Contains(ip) {
				// println(cc.Domain, " v4", ip, ipString, "index=", index)
				return 4
			}
		}
	}
	return 1
}

// getIPInfo 获取 IP 地址的地理位置、ASN 和前缀信息
func getIPInfo(ip net.IP, cityDB *geoip2.Reader, asnDB *geoip2.Reader) (*IPInfo, error) {
	// 获取地理位置
	cityRecord, err := cityDB.City(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get city information: %v", err)
	}

	// 获取 ASN 信息
	asnRecord, err := asnDB.ASN(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASN information: %v", err)
	}

	// 获取 IP 前缀
	var ipPrefix24, ipPrefix64, ipPrefix48 string
	// if ip.To4() != nil {
	// 	ipPrefix24 = fmt.Sprintf("%s/24", strings.Join(strings.Split(ip.String(), ".")[:3], "."))
	// } else {
	// 	ipPrefix64 = fmt.Sprintf("%s/64", strings.Join(strings.Split(ip.String(), ":")[:4], ":"))
	// 	ipPrefix48 = fmt.Sprintf("%s/48", strings.Join(strings.Split(ip.String(), ":")[:3], ":"))
	// }
	if ip.To4() != nil {
		// 对于IPv4地址
		ipParts := strings.Split(ip.String(), ".")
		if len(ipParts) >= 3 {
			ipPrefix24 = fmt.Sprintf("%s/24", strings.Join(ipParts[:3], "."))
		} else {
			// 处理错误情况，例如记录日志或返回错误
			log.Println("IPv4 address does not contain enough parts",ipParts)
		}
	} else {
		// 对于IPv6地址
		ipParts := strings.Split(ip.String(), ":")
		if len(ipParts) >= 4 {
			ipPrefix64 = fmt.Sprintf("%s/64", strings.Join(ipParts[:4], ":"))
		} else {
			// 处理错误情况，例如记录日志或返回错误
			log.Println("IPv6 address does not contain enough parts for /64 prefix",ipParts)
		}
		if len(ipParts) >= 3 {
			ipPrefix48 = fmt.Sprintf("%s/48", strings.Join(ipParts[:3], ":"))
		} else {
			// 处理错误情况，例如记录日志或返回错误
			log.Println("IPv6 address does not contain enough parts for /48 prefix",ipParts)
		}
	}

	info := IPInfo{
		CountryCode:      cityRecord.Country.IsoCode,
		City:             cityRecord.City.Names["en"],
		ASN:              asnRecord.AutonomousSystemNumber,
		IPPrefix24:       ipPrefix24,
		IPPrefix64:       ipPrefix64,
		IPPrefix48:       ipPrefix48,
		AutonomousSystem: asnRecord.AutonomousSystemOrganization,
	}

	return &info, nil
}

func CheckSameRegion(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 City database: %v", err)
	}
	defer cityDB.Close()

	var firstCountryCode string
	for i, ip := range ipList {
		info, err := getIPInfo(ip, cityDB, nil)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstCountryCode = info.CountryCode
		} else if firstCountryCode != info.CountryCode {
			return false, nil
		}
	}

	return true, nil
}

func CheckSameCity(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 City database: %v", err)
	}
	defer cityDB.Close()

	var firstCity string
	for i, ip := range ipList {
		info, err := getIPInfo(ip, cityDB, nil)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstCity = info.City
		} else if firstCity != info.City {
			return false, nil
		}
	}

	return true, nil
}

func CheckSameASN(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 ASN database: %v", err)
	}
	defer asnDB.Close()

	var firstASN uint
	for i, ip := range ipList {
		info, err := getIPInfo(ip, nil, asnDB)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstASN = info.ASN
		} else if firstASN != info.ASN {
			return false, nil
		}
	}

	return true, nil
}

func CheckSameIPv4Prefix24(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 City database: %v", err)
	}
	defer cityDB.Close()

	var firstPrefix24 string
	for i, ip := range ipList {
		if ip.To4() == nil {
			continue
		}
		info, err := getIPInfo(ip, cityDB, nil)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstPrefix24 = info.IPPrefix24
		} else if firstPrefix24 != info.IPPrefix24 {
			return false, nil
		}
	}

	return firstPrefix24 != "", nil
}

func CheckSameIPv6Prefix64(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 City database: %v", err)
	}
	defer cityDB.Close()

	var firstPrefix64 string
	for i, ip := range ipList {
		if ip.To4() != nil {
			continue
		}
		info, err := getIPInfo(ip, cityDB, nil)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstPrefix64 = info.IPPrefix64
		} else if firstPrefix64 != info.IPPrefix64 {
			return false, nil
		}
	}

	return firstPrefix64 != "", nil
}

func CheckSameIPv6Prefix48(ipList []net.IP) (bool, error) {
	if len(ipList) <= 1 {
		return false, nil
	}

	cityDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return false, fmt.Errorf("failed to open the GeoIP2 City database: %v", err)
	}
	defer cityDB.Close()

	var firstPrefix48 string
	for i, ip := range ipList {
		if ip.To4() != nil {
			continue
		}
		info, err := getIPInfo(ip, cityDB, nil)
		if err != nil {
			return false, err
		}
		if i == 0 {
			firstPrefix48 = info.IPPrefix48
		} else if firstPrefix48 != info.IPPrefix48 {
			return false, nil
		}
	}

	return firstPrefix48 != "", nil
}

// func CheckIPList(ipList []net.IP, cache *Cache.DNSCache) {
// 	// 检查IP列表
// 	// sameRegion, err := CheckSameRegion(ipList)
// 	// if err != nil {
// 	// 	log.Fatalf("Error checking same region: %v", err)
// 	// }
// 	sameCity, err := CheckSameCity(ipList)
// 	if err != nil {
// 		log.Fatalf("Error checking same city: %v", err)
// 	}
// 	sameASN, err := CheckSameASN(ipList)
// 	if err != nil {
// 		log.Fatalf("Error checking same ASN: %v", err)
// 	}
// 	samePrefix24, err := CheckSameIPv4Prefix24(ipList)
// 	if err != nil {
// 		log.Fatalf("Error checking same IPv4 /24 prefix: %v", err)
// 	}
// 	samePrefix64, err := CheckSameIPv6Prefix64(ipList)
// 	if err != nil {
// 		log.Fatalf("Error checking same IPv6 /64 prefix: %v", err)
// 	}
// 	samePrefix48, err := CheckSameIPv6Prefix48(ipList)
// 	if err != nil {
// 		log.Fatalf("Error checking same IPv6 /48 prefix: %v", err)
// 	}

// 	// if sameRegion {
// 	// 	cache.SetError("ANSintheSameCountry")
// 	// }
// 	if sameCity {
// 		cache.SetError("ANSintheSameCity")
// 	}
// 	if sameASN {
// 		cache.SetError("ANSintheSameAS")
// 	}
// 	if samePrefix24 {
// 		cache.SetError("ANSv4under24prefix")
// 	}
// 	if samePrefix64 {
// 		cache.SetError("ANSv6under64prefix")
// 	}
// 	if samePrefix48 {
// 		cache.SetError("ANSv6under48prefix")
// 	}

// }

func CheckIPList(ipList []net.IP, cache *Cache.DNSCache) {
	// 检查IP列表
	// sameRegion, err := CheckSameRegion(ipList)
	// if err != nil {
	// 	log.Fatalf("Error checking same region: %v", err)
	// }
	// if len(ipList) <= 1 {
	// 	return
	// }

	// sameCountry := true
	// sameCity := true
	sameASN := true
	samePrefix24 := true
	samePrefix64 := true
	samePrefix48 := true
	v4 := 0
	v6 := 0
	var firstInfo *IPInfo

	cityDB, err := geoip2.Open("pkg/Identify/GeoLite2-City.mmdb")
	if err != nil {
		// fmt.Printf("failed to open the GeoIP2 City database: %v /n", err)
		return
	}
	defer cityDB.Close()

	asnDB, err := geoip2.Open("pkg/Identify/GeoLite2-ASN.mmdb")
	if err != nil {
		// fmt.Printf("failed to open the GeoIP2 ASN database: %v /n", err)
		return
	}
	defer asnDB.Close()

	for i, ip := range ipList {
		info, _ := getIPInfo(ip, cityDB, asnDB)
		// fmt.Println(cache.Domain,ip,info.ASN)

		//fmt.Println(ip,info.CountryCode,info.City,info.ASN)

		if i == 0 {
			firstInfo = info
		} else {
			// if firstInfo.CountryCode != info.CountryCode {
			// 	sameCountry = false
			// }
			// if firstInfo.City != info.City {
			// 	sameCity = false
			// }
			if firstInfo.ASN != info.ASN {
				sameASN = false
			}
			if ip.To4() != nil {
				v4++
				if firstInfo.IPPrefix24 != info.IPPrefix24 && firstInfo.IPPrefix24 != "" && info.IPPrefix24 != "" {
					samePrefix24 = false
				}
				if firstInfo.IPPrefix24 == "" {
					firstInfo.IPPrefix24 = info.IPPrefix24
				}
			} else {
				v6++
				if firstInfo.IPPrefix48 != info.IPPrefix48 && firstInfo.IPPrefix48 != "" && info.IPPrefix48 != "" {
					samePrefix48 = false
				}
				if firstInfo.IPPrefix64 != info.IPPrefix64 && firstInfo.IPPrefix64 != "" && info.IPPrefix64 != "" {
					samePrefix64 = false
				}
				if firstInfo.IPPrefix48 == "" {
					firstInfo.IPPrefix48 = info.IPPrefix48
				}
				if firstInfo.IPPrefix64 == "" {
					firstInfo.IPPrefix64 = info.IPPrefix64
				}
			}
		}
	}

	// if sameCountry {
	// 	cache.SetError("ANSintheSameCountry")
	// }
	// if sameCity {
	// 	cache.SetError("ANSintheSameCity")
	// }
	if sameASN {
		cache.SetError("ANSintheSameAS")
	}
	if samePrefix24 && v4 > 1 {
		cache.SetError("ANSv4under24prefix")
	}
	if samePrefix64 && v6 > 1 {
		cache.SetError("ANSv6under64prefix")
	}
	if samePrefix48 && v6 > 1 {
		cache.SetError("ANSv6under48prefix")
	}
	return 

}
