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

package Resolver

import (
	"fmt"
	"net"
	"strings"
	"time"
)



// Root DNS server list (IPv4 mapped to corresponding domain name)
// Currently uses a single IPv4 root server; uncomment the full list below for production use
var RootServersv4 = map[string]string{
	"199.9.14.201": "b.root-servers.net",
	// "2001:500:200::b": "b.root-servers.net", // Uncomment for IPv6 support
}

var RootServersv6 = map[string]string{
	"2001:500:200::b": "b.root-servers.net",
	// "2001:500:200::b": "b.root-servers.net", // Uncomment for IPv6 support
}

// Optional full root DNS server list (IPv4 + IPv6) - uncomment and use as needed
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

// Alternative root DNS server list format (slice of IPs only) - uncomment and use as needed
// var rootZoneServers = []string{
// 	// IPv4 addresses
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
// 	// IPv6 addresses
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

// isIPv4 checks if the given address is an IPv4 address
func isIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}


// GetFirstNAddresses returns up to 'n' root server IP addresses based on the configured IP version in Rmap.
func (d *Rmap) GetFirstNAddresses(n int) []string {
	var filteredServers []string

	// Select root servers based on Rmap's IPversion
	switch d.IPversion {
	case 4:
		// IPv4 mode: use only IPv4 root servers
		for ip := range RootServersv4 {
			filteredServers = append(filteredServers, ip)
		}
	case 6:
		// IPv6 mode: use only IPv6 root servers
		for ip := range RootServersv6 {
			filteredServers = append(filteredServers, ip)
		}
	default:
		// Dual-stack mode (IPversion=0 or other): use both IPv4 and IPv6
		// Currently only adding IPv4 addresses first
		for ip := range RootServersv4 {
			filteredServers = append(filteredServers, ip)
		}
	}

	// Limit the number of returned addresses (return up to 'n'; if n <= 0 or exceeds available, return all)
	if n <= 0 || n > len(filteredServers) {
		return filteredServers
	}
	return filteredServers[:n]
}

// SetTimeOut sets read, write, and dial timeouts for DNS operations
func (d *Rmap) SetTimeOut(t time.Duration) {
	d.ReadTimeout = t
	d.WriteTimeout = t
	d.DialTimeout = t
}

func (d *Rmap) SetDNS(host string, ipVersion int) error {
    port := "53"
    var ip string

    // Split host and port (handles input with port)
    if strings.Contains(host, ":") {
        // Handle IPv6 with brackets (e.g., [2001:db8::1]:53)
        if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
            var err error
            ip, port, err = net.SplitHostPort(host)
            if err != nil {
                return fmt.Errorf("failed to parse IPv6 address with port: %w", err)
            }
            // Remove brackets from IPv6 address
            if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
                ip = ip[1 : len(ip)-1]
            }
        } else {
            // Handle IPv4 with port or plain IPv6 (without brackets)
            var err error
            ip, port, err = net.SplitHostPort(host)
            if err != nil {
                // Try as plain IPv6 (without port)
                ip = host
            }
        }
    } else {
        // Plain IP (no port)
        ip = host
    }
    port = "53"

    // Validate IP address
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    // Check IP type based on ipVersion
    switch ipVersion {
    case 4:
        // Allow only IPv4
        if parsedIP.To4() == nil {
            return fmt.Errorf("IPv4 required but got IPv6: %s", ip)
        }
        d.RemoteAddr = fmt.Sprintf("%s:%s", ip, port) // IPv4 doesn't need brackets
        // fmt.Println(d.RemoteAddr)

    case 6:
        // Allow only IPv6
        if parsedIP.To4() != nil {
            return fmt.Errorf("IPv6 required but got IPv4: %s", ip)
        }
        d.RemoteAddr = fmt.Sprintf("[%s]:%s", ip, port) // IPv6 requires brackets
        // fmt.Println(d.RemoteAddr, ip, port)

    default:
        // Dual-stack mode (support both IPv4 and IPv6)
        if parsedIP.To4() != nil {
            d.RemoteAddr = fmt.Sprintf("%s:%s", ip, port)
        } else {
            d.RemoteAddr = fmt.Sprintf("[%s]:%s", ip, port)
        }
    }

    return nil
}

// readTimeout returns the configured read timeout, or default if not set
func (d *Rmap) readTimeout() time.Duration {
	if d.ReadTimeout != 0 {
		return d.ReadTimeout
	}
	return 3 * time.Second
}

// SetRetry sets the number of retry attempts for DNS queries (default: 1)
// Returns the configured retry count for verification
func (d *Rmap) SetRetry(retryCount int) int {
	// Ensure retry count is at least 1 to avoid invalid retry logic
	if retryCount < 1 {
		retryCount = 1
	}
	// Note: Assumes the Rmap struct has a RetryCount field; uncomment below if applicable
	// d.RetryCount = retryCount
	return retryCount
}

// RemoveDuplicates removes duplicate strings from a slice and returns the unique result
func (d *Rmap) RemoveDuplicates(strs []string) []string {
	seen := make(map[string]bool)
	uniqueStrs := make([]string, 0, len(strs))

	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			uniqueStrs = append(uniqueStrs, s)
		}
	}

	return uniqueStrs
}