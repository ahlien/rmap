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
	"rmap/pkg/Cache"
	"rmap/pkg/Graph"
	"rmap/pkg/Identify"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Trace performs recursive DNS resolution similar to `Rmap +trace`, traversing root servers to resolve the target domain
// It builds a resolution graph, caches results, and handles cycle detection
func (d *Rmap) Trace(
	domain string,
	queryType uint16,
	graph *Graph.DNSGraph,
	cache *Cache.DNSCache,
	mu *sync.Mutex,
	mod int,
) []string {
	// Validate required parameters to avoid nil pointer dereferences
	if d == nil || graph == nil || cache == nil {
		fmt.Printf("Error: One or more required arguments (Rmap/Graph/Cache) are nil\n")
		return nil
	}

	// Initialize slice to store resolved IP addresses
	ipAddresses := make([]string, 0)

	// Add initial "begin" node to the resolution graph (level 0 = starting point)
	startNodeID := graph.AddNode(domain, "begin", queryType, Graph.Begin)
	graph.SetNodeLevel(domain, "begin", queryType, 0)

	switch d.IPversion {
		case 6:
			for rootIP, rootNS := range RootServersv6 {
				// Add root server node to the graph (mark as Root type)
				rootNodeID := graph.AddNode(domain, rootIP, queryType, Graph.Root)
				// Associate root server IP with its corresponding domain name
				graph.SetNodeNameServer(domain, rootIP, queryType, rootNS)
				// Add edge from start node to root server node
				graph.AddEdge(startNodeID, rootNodeID, "Begin -> Root Server")
				// Set root server zone to root zone (".")
				graph.SetNodeZone(domain, rootIP, dns.TypeAAAA, ".")

				// Recursively resolve the domain using the current root server
				d.Resolver(domain, dns.TypeA, rootIP, graph, cache, &ipAddresses)
				// Explicitly mark node type as Root (redundant but ensures consistency)
				graph.SetNodeType(rootNodeID, Graph.Root)
				// fmt.Println(rootIP)
				break
			}
		default:
			for rootIP, rootNS := range RootServersv4 {
				// Add root server node to the graph (mark as Root type)
				rootNodeID := graph.AddNode(domain, rootIP, queryType, Graph.Root)
				// Associate root server IP with its corresponding domain name
				graph.SetNodeNameServer(domain, rootIP, queryType, rootNS)
				// Add edge from start node to root server node
				graph.AddEdge(startNodeID, rootNodeID, "Begin -> Root Server")
				// Set root server zone to root zone (".")
				graph.SetNodeZone(domain, rootIP, dns.TypeA, ".")

				// Recursively resolve the domain using the current root server
				d.Resolver(domain, dns.TypeA, rootIP, graph, cache, &ipAddresses)
				// Explicitly mark node type as Root (redundant but ensures consistency)
				graph.SetNodeType(rootNodeID, Graph.Root)
				break
			}
		}




	// Collect cycle statistics from the resolution graph
	oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize := graph.GetCycleStats()
	// Record cycle-related errors in cache
	if oneNodeCycleCount > 0 {
		cache.SetError("OneCircularRef") // Single-node cycle detected
	}
	if multiNodeCycleCount > 0 {
		cache.SetError("MultiCircularRef") // Multi-node cycle detected
	}
	// Update cache with detailed cycle stats if any cycles exist
	if oneNodeCycleCount+multiNodeCycleCount > 0 {
		cache.UpdateCacheWithCycleStats(oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize)
	}

	// Execute module-specific operations based on the `mod` parameter
	switch mod {
	case 4:
		mu.Lock()
		defer mu.Unlock()
		cache.GetAnswerIPs() // Retrieve and process resolved answer IPs
	case 5:
		mu.Lock()
		defer mu.Unlock()
		cache.GetNSRecords() // Retrieve and process NS records
		cache.PrintAuthoritativeNSIPs()
	case 6:
		mu.Lock()
		defer mu.Unlock()
		cache.GetAAAARecords() // Retrieve and process AAAA (IPv6) records
	case 7:
		mu.Lock()
		defer mu.Unlock()
		graph.PrintGraph() // Print detailed graph structure
	case 8:
		mu.Lock()
		defer mu.Unlock()
		cache.GetIPv6Nameservers() // Retrieve and process IPv6 nameservers
	case 9:
		mu.Lock()
		defer mu.Unlock()
		graph.PrintCycles() // Print detected cycles in the graph
	default:
		// No operation for unrecognized module IDs
	}

	// Return deduplicated list of resolved IP addresses
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

// processDNSAnswerSection parses the ANSWER section of a DNS response, extracts records (A/AAAA/CNAME/NS/SOA/DNAME),
// updates the resolution graph and cache, and returns structured DNS message data
func (d *Rmap) processDNSAnswerSection(
	msg *dns.Msg,
	server string,
	domain string,
	parentNodeID int,
	graph *Graph.DNSGraph,
	cache *Cache.DNSCache,
	GetIP *[]string,
) Cache.DNSMessage {
	// Map to track NS records and their associated glue IPs
	nsMap := make(map[string]*Cache.NSRecord)
	// Slice to track NS records missing glue IPs
	missingGlue := make([]string, 0)
	// Flag indicating if all NS records have associated glue IPs
	allHaveGlue := true

	// Track duplicate records in the ANSWER section (prevents redundant processing)
	seenRecords := make(map[string]bool)

	// Iterate over each resource record (RR) in the ANSWER section
	for _, rr := range msg.Answer {
		// Generate a unique string representation of the RR to detect duplicates
		rrStr := fmt.Sprintf("%v", rr)
		if seenRecords[rrStr] {
			cache.SetError("SameRRinAnswer") // Mark duplicate RR error in cache
		}
		seenRecords[rrStr] = true

		// Process RR based on its type
		switch record := rr.(type) {
		case *dns.DNAME:
			// Collect DNAME records (maps one domain to another)
			cache.AddDnameRecord(record.Target)

		case *dns.SOA:
			// Detect SOA records in ANSWER section (uncommon for standard resolution)
			cache.SetError("SOAInAnswerFound")

		case *dns.OPT:
			// OPT records should not appear in ANSWER section (reserved for EXTRA)
			cache.SetError("OPTError")

		case *dns.A:
			// Process A (IPv4) records
			ipv4 := record.A
			// Associate IPv4 with its corresponding NS record (if exists)
			if nsRecord, exists := nsMap[record.Hdr.Name]; exists {
				nsRecord.IPv4GlueIPs = append(nsRecord.IPv4GlueIPs, ipv4)
			} else {
				nsMap[record.Hdr.Name] = &Cache.NSRecord{
					NameServer:  record.Hdr.Name,
					IPv4GlueIPs: []net.IP{ipv4},
				}
			}

			// Add IPv4 to the resolved IP list
			*GetIP = append(*GetIP, ipv4.To16().String())
			// Add IPv4 node to the graph and connect to parent node
			ipv4NodeID := graph.AddNode(domain, ipv4.String(), dns.TypeA, Graph.Common)
			graph.AddEdge(parentNodeID, ipv4NodeID, "Resolved A (IPv4)")

			// If resolving the target domain, mark node as leaf (A record) and cache the IP
			if cache.Domain == domain {
				graph.AddNode(domain, ipv4.String(), dns.TypeA, Graph.LeaveA)
				// Trigger IPv6 (AAAA) resolution for the same domain
				d.Resolver(domain, dns.TypeAAAA, server, graph, cache, GetIP)
				// Cache the resolved IPv4 as an answer IP
				cache.AddAnswerIP(ipv4.String())
				cache.SetError("SuccessfullyParsed") // Mark successful parsing
			}

		case *dns.AAAA:
			// Process AAAA (IPv6) records
			ipv6 := record.AAAA
			// Collect AAAA records and IPv6 nameservers in cache
			cache.AddAAAARecord(rrStr)
			cache.AddIPv6Nameserver(ipv6.String())

			// Associate IPv6 with its corresponding NS record (if exists)
			if nsRecord, exists := nsMap[record.Hdr.Name]; exists {
				nsRecord.IPv6GlueIPs = append(nsRecord.IPv6GlueIPs, ipv6)
			} else {
				nsMap[record.Hdr.Name] = &Cache.NSRecord{
					NameServer:  record.Hdr.Name,
					IPv6GlueIPs: []net.IP{ipv6},
				}
			}

			// Add IPv6 to the resolved IP list
			*GetIP = append(*GetIP, ipv6.To16().String())
			// Add IPv6 node to the graph and connect to parent node
			ipv6NodeID := graph.AddNode(domain, ipv6.String(), dns.TypeA, Graph.Common)
			graph.AddEdge(parentNodeID, ipv6NodeID, "Resolved AAAA (IPv6)")

			// If resolving the target domain, mark node as leaf (AAAA record) and cache the IP
			if cache.Domain == domain {
				graph.AddNode(domain, ipv6.String(), dns.TypeA, Graph.LeaveAAAA)
				cache.AddAnswerIP(ipv6.String())
				cache.SetError("SuccessfullyParsed") // Mark successful parsing
			}

		case *dns.NS:
			// Process NS records (authoritative nameservers)
			nsDomain := record.Ns
			// Add NS record to map if not already present
			if _, exists := nsMap[nsDomain]; !exists {
				nsMap[nsDomain] = &Cache.NSRecord{NameServer: nsDomain}
			}

			// Add "NS begin" node to the graph and connect to parent node
			nsStartNodeID := graph.AddNode(nsDomain, "ns_begin", dns.TypeA, Graph.Begin)
			graph.AddEdge(parentNodeID, nsStartNodeID, "Discovered NS Record")

		case *dns.CNAME:
			// Process CNAME records (domain aliases)
			cnameTarget := record.Target

			// RFC 1034 Compliance: A domain should have only one CNAME record (no other record types)
			if len(msg.Answer) > 1 {
				cache.SetError("NotOnlyOneCnameRR") // Mark multiple CNAME error
			}

			// Cache the CNAME target and check for CNAME cycles
			cache.AddCNameRecord(cnameTarget)
			if cache.HasCNameCycle() || cnameTarget == domain {
				cache.SetError("CNAMECircularRef") // Mark CNAME cycle error
			}

			// // Uncomment for testing: Add CNAME target as an NS record
			// cache.AddNSRecord(cnameTarget)

			// Add "CNAME begin" node to the graph and connect to parent node
			cnameStartNodeID := graph.AddNode(cnameTarget, "cname_begin", dns.TypeCNAME, Graph.LeaveCNAME)
			graph.AddEdge(parentNodeID, cnameStartNodeID, "Resolved CNAME")

			switch d.IPversion {
				case 6:
					for rootIP, rootNS := range RootServersv6 {
						// Add root server node for CNAME resolution
						rootNodeID := graph.AddNode(cnameTarget, rootIP, dns.TypeA, Graph.Root)
						graph.SetNodeNameServer(cnameTarget, rootIP, dns.TypeA, rootNS)
						// Connect CNAME start node to root server node
						graph.AddEdge(cnameStartNodeID, rootNodeID, "CNAME -> Root Server")
						// Set root server zone to root zone (".")
						graph.SetNodeZone(cnameTarget, rootIP, dns.TypeAAAA, ".")
						// Recursively resolve the CNAME target
						d.Resolver(cnameTarget, dns.TypeA, rootIP, graph, cache, GetIP)
					}
				default:
					for rootIP, rootNS := range RootServersv4 {
						// Add root server node for CNAME resolution
						rootNodeID := graph.AddNode(cnameTarget, rootIP, dns.TypeA, Graph.Root)
						graph.SetNodeNameServer(cnameTarget, rootIP, dns.TypeA, rootNS)
						// Connect CNAME start node to root server node
						graph.AddEdge(cnameStartNodeID, rootNodeID, "CNAME -> Root Server")
						// Set root server zone to root zone (".")
						graph.SetNodeZone(cnameTarget, rootIP, dns.TypeA, ".")
						// Recursively resolve the CNAME target
						d.Resolver(cnameTarget, dns.TypeA, rootIP, graph, cache, GetIP)
					}
				}



			// Use resolved CNAME IPs to continue resolving the original domain
			for _, ipStr := range UniqueIPs(*GetIP) {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					fmt.Printf("Invalid IP address (resolved from CNAME): %s\n", ipStr)
					continue
				}

				// Get node ID for the CNAME-resolved IP and connect to original domain node
				cnameIPNodeID, _ := graph.GetNodeID(cnameTarget, ip.String(), dns.TypeA)
				domainIPNodeID := graph.AddNode(domain, ip.String(), dns.TypeA, Graph.Common)
				graph.AddEdge(cnameIPNodeID, domainIPNodeID, "CNAME IP -> Original Domain")

				// Continue resolving the original domain using the CNAME-resolved IP
				d.Resolver(domain, dns.TypeA, ip.To16().String(), graph, cache, GetIP)
			}
		}
	}

	// Convert nsMap to a slice of NSRecord and identify NS records missing glue IPs
	var nsRecords []Cache.NSRecord
	for _, nsRecord := range nsMap {
		nsRecords = append(nsRecords, *nsRecord)
		// Check if NS record has no glue IPs (IPv4 or IPv6)
		if len(nsRecord.IPv4GlueIPs) == 0 && len(nsRecord.IPv6GlueIPs) == 0 {
			missingGlue = append(missingGlue, nsRecord.NameServer)
			allHaveGlue = false
		}
	}

	// Return structured DNS message data
	return Cache.DNSMessage{
		NSRecords:   nsRecords,
		MissingGlue: missingGlue,
		AllHaveGlue: allHaveGlue,
	}
}

// extractDNSMessage parses the NS and EXTRA sections of a DNS response to extract NS records and glue IPs,
// updates the resolution graph and cache, and returns structured DNS message data
func extractDNSMessage(
	domain string,
	msg *dns.Msg,
	parentNodeID int,
	cache *Cache.DNSCache,
	graph *Graph.DNSGraph,
	server string,
) Cache.DNSMessage {
	if msg == nil || cache == nil || graph == nil {
		fmt.Printf("Error: DNS message, cache, or graph is nil in extractDNSMessage\n")
		return Cache.DNSMessage{}
	}

	nsMap := make(map[string]*Cache.NSRecord)
	var ipList []net.IP
	seenExtraRecords := make(map[string]bool)

	// Parse EXTRA section (glue IPs)
	for _, rr := range msg.Extra {
		rrStr := fmt.Sprintf("%v", rr)
		if seenExtraRecords[rrStr] {
			cache.SetError("SameRRinAdditional") // Fixed typo
		}
		seenExtraRecords[rrStr] = true

		switch record := rr.(type) {
		case *dns.A:
			ipv4 := record.A
			ipList = append(ipList, ipv4)

			if nsRecord, exists := nsMap[record.Hdr.Name]; exists {
				nsRecord.IPv4GlueIPs = append(nsRecord.IPv4GlueIPs, ipv4)
			} else {
				nsMap[rr.Header().Name] = &Cache.NSRecord{
					NameServer:  rr.Header().Name,
					IPv4GlueIPs: []net.IP{ipv4},
				}
			}

			ipv4NodeID := graph.AddNode(domain, ipv4.String(), dns.TypeA, Graph.Common)
			graph.SetNodeNameServer(domain, ipv4.String(), dns.TypeA, rr.Header().Name)
			graph.AddEdge(parentNodeID, ipv4NodeID, "Glue A (IPv4)")

		case *dns.AAAA:
			ipv6 := record.AAAA
			ipList = append(ipList, ipv6)
			cache.AddAAAARecord(rrStr)
			cache.AddIPv6Nameserver(ipv6.String())

			if nsRecord, exists := nsMap[record.Hdr.Name]; exists {
				nsRecord.IPv6GlueIPs = append(nsRecord.IPv6GlueIPs, ipv6)
			} else {
				nsMap[rr.Header().Name] = &Cache.NSRecord{
					NameServer:  rr.Header().Name,
					IPv6GlueIPs: []net.IP{ipv6},
				}
			}

			ipv6NodeID := graph.AddNode(domain, ipv6.String(), dns.TypeAAAA, Graph.Common)
			graph.SetNodeNameServer(domain, ipv6.String(), dns.TypeAAAA, rr.Header().Name)
			graph.AddEdge(parentNodeID, ipv6NodeID, "Glue AAAA (IPv6)")
		}
	}

	// Skip IP check for root/TLD
	shouldSkipIPCheck := false
	for _, nsrr := range msg.Ns {
		if nsRecord, ok := nsrr.(*dns.NS); ok {
			dotCount := strings.Count(nsRecord.Header().Name, ".")
			if dotCount <= 1 {
				shouldSkipIPCheck = true
				break
			}
		}
	}
	if !shouldSkipIPCheck {
		Identify.CheckIPList(ipList, cache)
	}

	dnsMsg := Cache.DNSMessage{AllHaveGlue: true}
	seenAuthorityRecords := make(map[string]bool)

	// Parse AUTHORITY section (NS / SOA / DNAME)
	for _, nsrr := range msg.Ns {
		rrStr := fmt.Sprintf("%v", nsrr)
		if seenAuthorityRecords[rrStr] {
			cache.SetError("SameRRinAuthority")
		}
		seenAuthorityRecords[rrStr] = true

		switch record := nsrr.(type) {
		case *dns.DNAME:
			cache.AddDnameRecord(record.Target)

		case *dns.NS:
			nsDomain := record.Ns
			cache.AddNSRecord(nsDomain, server)

			if nsRecord, exists := nsMap[nsDomain]; exists {
				dnsMsg.NSRecords = append(dnsMsg.NSRecords, *nsRecord)
				for _, ipv4 := range nsRecord.IPv4GlueIPs {
					graph.SetNodeZone(domain, ipv4.String(), dns.TypeA, nsrr.Header().Name)
				}
				for _, ipv6 := range nsRecord.IPv6GlueIPs {
					graph.SetNodeZone(domain, ipv6.String(), dns.TypeAAAA, nsrr.Header().Name)
				}

				parentTLD := extractTLD(nsrr.Header().Name)
				nsTLD := extractTLD(nsDomain)
				if parentTLD != nsTLD && parentTLD != "" {
					cache.SetError("NonRootAuthOverride")
					cache.SetError("AuthOverrideWithGlueIP")
				}
			} else {
				dnsMsg.NSRecords = append(dnsMsg.NSRecords, Cache.NSRecord{NameServer: nsDomain})
				dnsMsg.MissingGlue = append(dnsMsg.MissingGlue, nsDomain)
				dnsMsg.AllHaveGlue = false

				parentTLD := extractTLD(nsrr.Header().Name)
				nsTLD := extractTLD(nsDomain)
				if parentTLD != nsTLD {
					cache.SetError("NonRootAuthOverride")
				} else {
					cache.SetError("CircularDependencies")
				}

				nsNodeID := graph.AddNode(nsDomain, "ns_begin", dns.TypeA, Graph.NsNotGlueIP)
				cache.SetError("NSNotGlueIP")
				cache.AddGluelessNSRecord(nsDomain)
				graph.AddEdge(parentNodeID, nsNodeID, "Glue-less NS")
			}

		case *dns.SOA:
			cache.SetError("SOAInAuthority")
			graph.SetNodeType(parentNodeID, Graph.SOA)
		}

		if nsrr.Header().Name == "." {
			cache.SetError("RedirectToRoot")
		}
	}

	return dnsMsg
}


// extractTLD extracts the top-level domain (TLD) from a fully qualified domain name (FQDN)
func extractTLD(domain string) string {
	if domain == "." { // Root domain has no TLD
		return ""
	}
	// Split domain into labels (e.g., "example.com." -> ["example", "com"])
	parts := dns.SplitDomainName(domain)
	if len(parts) < 2 {
		return "" // Not enough labels for a TLD (e.g., "localhost")
	}
	// Combine last two labels to form TLD (e.g., "com" from ["example", "com"])
	return strings.ToLower(parts[len(parts)-2] + "." + parts[len(parts)-1])
}

// Mapmerge merges two string maps, with entries from the second map overriding the first on key collision
func Mapmerge(map1, map2 map[string]string) map[string]string {
	merged := make(map[string]string)
	// Add all entries from first map
	for k, v := range map1 {
		merged[k] = v
	}
	// Add entries from second map (overwriting existing keys)
	for k, v := range map2 {
		merged[k] = v
	}
	return merged
}

// UniqueIPs returns a deduplicated slice of IP addresses
func UniqueIPs(ips []string) []string {
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, exists := seen[ip]; !exists {
			seen[ip] = struct{}{}
			unique = append(unique, ip)
		}
	}
	return unique
}

// CheckIPRouting verifies if an IP address is routable (not invalid/reserved)
func CheckIPRouting(server string, cache *Cache.DNSCache, domain string) bool {
	switch Identify.IsPrivateIP(server, cache) {
	case 0:
		cache.SetError("InvalidIP") // Invalid IP format
		return false
	case 4:
		cache.SetError("IPv4Reserved") // Reserved IPv4 address
		return false
	case 6:
		cache.SetError("IPv6Reserved") // Reserved IPv6 address
	}
	return true // IP is routable
}

// checkResponseRCode validates the DNS response code (RCODE) and updates cache/graph accordingly
func checkResponseRCode(rcode int, domain string, server string, cache *Cache.DNSCache, graph *Graph.DNSGraph) bool {
	nodeID, _ := graph.GetNodeID(domain, server, dns.TypeA)

	switch rcode {
	case dns.RcodeSuccess: // RCODE 0: No error
		return true

	case dns.RcodeFormatError: // RCODE 1: Format error
		graph.SetNodeType(nodeID, Graph.FormErr)
		cache.SetError("FormatError")

	case dns.RcodeServerFailure: // RCODE 2: Server failure
		graph.SetNodeType(nodeID, Graph.ServerFailure)
		cache.SetError("ServerFailure")

	case dns.RcodeNameError: // RCODE 3: Non-existent domain
		graph.SetNodeType(nodeID, Graph.NXDOMAIN)
		cache.SetError("NXDOMAIN")

	case dns.RcodeNotImplemented: // RCODE 4: Not implemented
		graph.SetNodeType(nodeID, Graph.NotImplemented)
		cache.SetError("NotImplemented")

	case dns.RcodeRefused: // RCODE 5: Refused
		graph.SetNodeType(nodeID, Graph.Refused)
		cache.SetError("Refused")

	case dns.RcodeYXDomain: // RCODE 6: Name exists when it should not
		graph.SetNodeType(nodeID, Graph.YXDomain)
		cache.SetError("YXDomain")

	case 7: // RCODE 7: RR set exists when it should not
		graph.SetNodeType(nodeID, Graph.YXRRSet)
		cache.SetError("YXRRSet")

	case 8: // RCODE 8: RR set does not exist
		graph.SetNodeType(nodeID, Graph.NXRRSet)
		cache.SetError("NXRRSet")

	case dns.RcodeNotAuth: // RCODE 9: Server not authoritative
		graph.SetNodeType(nodeID, Graph.NotAuthorized)
		cache.SetError("NotAuth")

	case dns.RcodeNotZone: // RCODE 10: Name not in zone
		graph.SetNodeType(nodeID, Graph.NotInZone)
		cache.SetError("NotZone")
	}

	return false // RCODE indicates an error
}

// handleCacheHit processes cached DNS records, updating the resolution graph with cached data
func handleCacheHit(domain string, server string, cache *Cache.DNSCache, graph *Graph.DNSGraph) error {
	// Retrieve cached IPs for the domain/server/type
	cachedIPs := cache.GetIPsByDNSRecordKey(domain, server, dns.TypeA)
	if len(cachedIPs) == 0 {
		return fmt.Errorf("no cached records found for %s@%s", domain, server)
	}

	// Get parent node ID for graph edges
	parentNodeID, _ := graph.GetNodeID(domain, server, dns.TypeA)

	// Add cached IPs to graph and connect to parent node
	for ns, ip := range cachedIPs {
		ipNodeID := graph.AddNode(domain, ip, dns.TypeA, Graph.Common)
		graph.SetNodeNameServer(domain, ip, dns.TypeA, ns)
		graph.AddEdge(parentNodeID, ipNodeID, "Cached IP")
	}

	return nil
}

// handlePacket processes the result of a DNS exchange, updating the graph with status information
func handlePacket(graph *Graph.DNSGraph, cache *Cache.DNSCache, status ExchangeStatus, domain string, msgType uint16, server string, qType uint16) bool {
	nodeID, _ := graph.GetNodeID(domain, server, qType)

	switch status {
	case Normal:
		graph.SetNodeType(nodeID, Graph.Common)
		return true

	case Timeout:
		graph.SetNodeType(nodeID, Graph.Timeout)
		return false

	case TxIDMismatch:
		graph.SetNodeType(nodeID, Graph.IDMisMatch)
		return false

    case Failure:  
        graph.SetNodeType(nodeID, Graph.ExchangeFailure)
        return false
    }

	return false
}

// checkRecursionAvailable checks if a DNS server incorrectly returns Recursion Available (RA=1) for non-recursive queries
func checkRecursionAvailable(cache *Cache.DNSCache, graph *Graph.DNSGraph, raFlag bool, server string, domain string, qType uint16) error {
    if raFlag {
        // RA=1 indicates potential hijacking in non-recursive resolution
        nodeID, _ := graph.GetNodeID(domain, server, dns.TypeA)
        graph.SetNodeType(nodeID, Graph.Hijack)
        cache.SetError("RecursionAvailable")
    }
    return nil
}

// checkIP validates an IP address format and configures the DNS client with it
func (d *Rmap) checkIP(server string, domain string, msgType uint16, cache *Cache.DNSCache, graph *Graph.DNSGraph) bool {
    // Validate IP and configure RemoteAddr using SetDNS
    if err := d.SetDNS(server, cache.Version); err != nil {
        nodeID, _ := graph.GetNodeID(domain, server, dns.TypeA)
        graph.SetNodeType(nodeID, Graph.IPError)
        return false
    }
    return true
}




// checkIPNsRecords verifies that NS records exist in the response
func checkIPNsRecords(nsCount int, server string, domain string, msgType uint16, cache *Cache.DNSCache, graph *Graph.DNSGraph) bool {
	nodeID, _ := graph.GetNodeID(domain, server, dns.TypeA)
	if nsCount == 0 {
		graph.SetNodeType(nodeID, Graph.NoNsRecord)
		cache.SetError("NoNsRecordFound")
		return false
	}
	return true
}

// CheckResponseEDE parses Extended DNS Errors (EDE) from the OPT record and updates the cache
func CheckResponseEDE(msg *dns.Msg, domain string, server string, cache *Cache.DNSCache, graph *Graph.DNSGraph) bool {
	hasEDE := false

	if msg.Extra == nil {
		return hasEDE
	}

	// Search for OPT records containing EDE options
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					hasEDE = true
					// Map EDE code to error string
					switch ede.InfoCode {
					case 0:
						cache.SetError("OtherError")
					case 1:
						cache.SetError("UnsupportedDNSKEYAlgorithm")
					case 2:
						cache.SetError("UnsupportedDSRmapestType")
					case 3:
						cache.SetError("StaleAnswer")
					case 4:
						cache.SetError("ForgedAnswer")
					case 5:
						cache.SetError("DNSSECIndeterminate")
					case 6:
						cache.SetError("DNSSECBogus")
					case 7:
						cache.SetError("SignatureExpired")
					case 8:
						cache.SetError("SignatureNotYetValid")
					case 9:
						cache.SetError("DNSKEYMissing")
					case 10:
						cache.SetError("RRSIGsMissing")
					case 11:
						cache.SetError("NoZoneKeyBitSet")
					case 12:
						cache.SetError("NSECMissing")
					case 13:
						cache.SetError("CachedError")
					case 14:
						cache.SetError("NotReady")
					case 15:
						cache.SetError("Blocked")
					case 16:
						cache.SetError("Censored")
					case 17:
						cache.SetError("Filtered")
					case 18:
						cache.SetError("Prohibited")
					case 19:
						cache.SetError("StaleNXDOMAINAnswer")
					case 20:
						cache.SetError("NotAuthoritative")
					case 21:
						cache.SetError("NotSupported")
					case 22:
						cache.SetError("NoReachableAuthority")
					case 23:
						cache.SetError("NetworkError")
					case 24:
						cache.SetError("InvalidData")
					default:
						fmt.Printf("Unknown EDE code %d for domain %s: %s\n", ede.InfoCode, domain, ede.ExtraText)
					}
				}
			}
		}
	}

	return hasEDE
}