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
	"net"
	"time"
	"sync"

	"github.com/miekg/dns"
)

// // Rmap holds configuration and state for DNS resolution operations
// type Rmap struct {
// 	Domain       string
// 	RemoteAddr   string
// 	DialTimeout  time.Duration
// 	WriteTimeout time.Duration
// 	ReadTimeout  time.Duration
// 	Protocol     string
// 	Retry        int
// 	IPversion    int
// }

// Rmap stores all configuration, state, and associated resources needed for DNS resolution operations.
type Rmap struct {
	// 1. Core configuration fields
	Domain        string        // Target domain (for single-domain mode, corresponds to -d flag)
	RemoteAddr    string        // Target DNS server address (optional)
	DialTimeout   time.Duration // Connection timeout
	WriteTimeout  time.Duration // Write timeout
	ReadTimeout   time.Duration // Read timeout
	Protocol      string        // Network protocol (tcp/udp, corresponds to -proto flag)
	Retry         int           // Number of retry attempts
	IPversion     int           // IP version (0=dual-stack, 4=IPv4, 6=IPv6, corresponds to -v flag)

	// 2. Batch / output related parameters
	DomainListFile string // Path to domain list file (batch mode, corresponds to -l flag)
	PoolSize       int    // Worker pool size (concurrent parsing, corresponds to -p flag)
	OutputFile     string // Output file path (corresponds to -output flag)
	Mode           int    // Operation mode (1-9, corresponds to -mod flag)

	// 3. Deferred-initialization resources (dependent on domain/version, not created in NewRmap)
	ErrorCounters map[string]int   // Error statistics (used in batch mode)
	Cache         *Cache.DNSCache  // DNS cache instance (dependent on domain + IPversion)
	Graph         *Graph.DNSGraph  // DNS graph instance (dependent on domain)
	Mutex         *sync.Mutex      // Mutex to ensure concurrency safety
}

// NewRmap constructor: initializes fields that do not have external dependencies.
// Cache/Graph are left nil for later deferred initialization.
func NewRmap() *Rmap {
	return &Rmap{
		// Default timeouts (5 seconds, can be modified later)
		DialTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
		// Default retry attempts (2)
		Retry: 2,
		// Default protocol (udp, aligned with command-line default)
		Protocol: "udp",
		// Initialize reference types (no dependencies, can be created directly)
		ErrorCounters: make(map[string]int),
		Mutex:         &sync.Mutex{},
		// Cache/Graph remain nil until domain/version are explicitly set
		Cache: nil,
		Graph: nil,
	}
}

// InitCacheAndGraph defers the initialization of Cache and Graph (for single-domain mode).
// Must be called after setting Rmap.Domain and Rmap.IPversion.
func (r *Rmap) InitCacheAndGraph() error {
	// Validate required parameters
	if r.Domain == "" {
		return fmt.Errorf("domain not set (call InitCacheAndGraph after assigning Rmap.Domain)")
	}
	if r.IPversion < 0 || r.IPversion > 6 {
		return fmt.Errorf("invalid IPversion %d (must be 0, 4, or 6)", r.IPversion)
	}

	// Initialize DNS cache with domain and IP version
	r.Cache = Cache.NewDNSCache(r.Domain, r.IPversion)
	// Initialize DNS graph with domain
	r.Graph = Graph.NewGraph(r.Domain)

	return nil
}


func (r *Rmap) Clone() *Rmap {
    // Note: Only basic types and pointers are copied; Cache and Graph are not shared
    newR := *r        // Perform a shallow copy first
    newR.Cache = nil   // Initialize Cache independently
    newR.Graph = nil   // Initialize Graph independently

    // ErrorCounters and Mutex can be shared, or copied as needed
    // If independent error statistics are desired for each goroutine, a deep copy of the map can be performed
    return &newR
}




// Resolver performs recursive DNS resolution for the given domain, record type, and target server
// It manages caching, graph traversal (to avoid cycles), and error handling
func (d *Rmap) Resolver(
	domain string,
	msgType uint16,
	server string,
	graph *Graph.DNSGraph,
	cache *Cache.DNSCache,
	GetIP *[]string,
) ([]string, error) {
	// Add authoritative NS IP to cache
	cache.AddAuthoritativeNSIP(server)

	// Cycle detection: check if this (domain, server, record type) node has been visited
	if exists := graph.IsNodeVisited(domain, server, msgType); exists {
		return nil, nil
	}
	// Mark node as visited to prevent reprocessing
	graph.MarkNodeVisited(domain, server, msgType)


	// Validate IP address format and basic connectivity
	if !d.checkIP(server, domain, msgType, cache, graph) {
		return nil, nil
	}

	// Check if the configured IP is routable
	if !CheckIPRouting(server, cache, domain) {
		// Handle unroutable IP error (no return value as error is logged/cached internally)
		return nil, nil
	}

	// Check cache hit first to avoid redundant DNS queries
	if cache.IsCacheHit(domain, server, dns.TypeA) {
		handleCacheHit(domain, server, cache, graph)
		return nil, nil
	}

	// No cache hit: send DNS query to get response
	msg, status := d.GetMsg(msgType, domain)
	// fmt.Println(msg)
	// Process packet status (e.g., timeout, TXID mismatch)
	if !handlePacket(graph, cache, status, domain, msgType, server, msgType) {
		return nil, nil
	}

	// Handle nil response (typically due to timeout)
	if msg == nil {
		cache.SetError("TimeoutOccurred")
		return nil, nil
	}


	// Validate response RCODE (e.g., NOERROR, SERVFAIL)
	if !checkResponseRCode(msg.Rcode, domain, server, cache, graph) {
		// Check EDE (Extended DNS Error) if no answer records exist
		if len(msg.Answer) == 0 {
			CheckResponseEDE(msg, domain, server, cache, graph)
		}
		// Check if recursion is available in the response
		checkRecursionAvailable(cache, graph, msg.MsgHdr.RecursionAvailable, server, domain, msgType)
		return nil, nil
	}

	// Check if recursion is available in the response
	checkRecursionAvailable(cache, graph, msg.MsgHdr.RecursionAvailable, server, domain, msgType)

	parentNode, _ := graph.GetNodeID(domain, server, msgType)

	// Case 1: No answer records (need to process NS records for further resolution)
	if len(msg.Answer) == 0 {
		// Check if NS records exist in the response
		if !checkIPNsRecords(len(msg.Ns), server, domain, msgType, cache, graph) {
			return nil, nil
		}
		// Check EDE for additional error context
		CheckResponseEDE(msg, domain, server, cache, graph)

		// Extract DNS message components (NS records, glue records, etc.)
		package1 := extractDNSMessage(domain, msg, parentNode, cache, graph, server)

		// Process each NS record to resolve its IP (if no glue records exist)
		for _, ns := range package1.NSRecords {
			// Resolve NS IP if no glue records are present
			if len(ns.IPv4GlueIPs) == 0 && len(ns.IPv6GlueIPs) == 0 {
				var nsIPs []string
				// Create starting node for NS resolution (mark as "ns_begin")
				nsStartNode, _ := graph.GetNodeID(ns.NameServer, "ns_begin", dns.TypeA)
				graph.AddEdge(parentNode, nsStartNode, "NS has no glue IP")


				// Resolve NS IP using root DNS servers
				switch d.IPversion {
				case 6:
					for rootIP, rootNS := range RootServersv6 {
						// Add root server node to the graph
						rootNode := graph.AddNode(ns.NameServer, rootIP, dns.TypeAAAA, Graph.Root)
						graph.AddEdge(nsStartNode, rootNode, "Query root server for NS IP")
						// Set root server zone (root zone: ".")
						graph.SetNodeZone(domain, rootIP, dns.TypeAAAA, ".")
						// Recursively resolve NS IP using root server
						d.Resolver(ns.NameServer, dns.TypeA, rootIP, graph, cache, &nsIPs)
						// Associate root IP with its corresponding NS domain
						graph.SetNodeNameServer(ns.NameServer, rootIP, dns.TypeAAAA, rootNS)
					}
				default:
					for rootIP, rootNS := range RootServersv4 {
						// Add root server node to the graph
						rootNode := graph.AddNode(ns.NameServer, rootIP, dns.TypeA, Graph.Root)
						graph.AddEdge(nsStartNode, rootNode, "Query root server for NS IP")
						// Set root server zone (root zone: ".")
						graph.SetNodeZone(domain, rootIP, dns.TypeA, ".")
						// Recursively resolve NS IP using root server
						d.Resolver(ns.NameServer, dns.TypeA, rootIP, graph, cache, &nsIPs)
						// Associate root IP with its corresponding NS domain
						graph.SetNodeNameServer(ns.NameServer, rootIP, dns.TypeA, rootNS)
					}
				}
			
				// Deduplicate resolved NS IPs and add to glue records
				for _, ipStr := range UniqueIPs(nsIPs) {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						fmt.Printf("Invalid IP address for NS %s: %s\n", ns.NameServer, ipStr)
						continue
					}
					// Classify IP version and add to glue records
					if ip.To4() != nil {
						ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, ip)
					} else {
						ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, ip)
					}
					// Add edge from NS node to resolved IP node
					nsIPNode, _ := graph.GetNodeID(ns.NameServer, ip.String(), dns.TypeA)
					domainIPNode := graph.AddNode(domain, ip.String(), dns.TypeA, Graph.Common)
					graph.AddEdge(nsIPNode, domainIPNode, "NS IP resolved, continue domain resolution")
				}
			}

			// Recursively resolve original domain using NS glue IPs
			for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
				d.Resolver(domain, dns.TypeA, ip.To16().String(), graph, cache, GetIP)
			}

			// Cache the NS records for future queries
			cache.AddRecord(domain, server, dns.TypeA, package1.NSRecords)
		}
	} else {
		// Case 2: Answer records exist (process answer section)
		package2 := d.processDNSAnswerSection(msg, server, domain, parentNode, graph, cache, GetIP)

		// If not all NS records have glue IPs, resolve missing ones
		if !package2.AllHaveGlue {
			for _, ns := range package2.NSRecords {
				if len(ns.IPv4GlueIPs) == 0 && len(ns.IPv6GlueIPs) == 0 {
					var nsIPs []string
					// Create starting node for NS resolution
					nsStartNode, _ := graph.GetNodeID(ns.NameServer, "ns_begin", dns.TypeA)

					switch d.IPversion {
					case 6:
						for rootIP, rootNS := range RootServersv6 {
							// Add root server node to the graph
							rootNode := graph.AddNode(ns.NameServer, rootIP, dns.TypeAAAA, Graph.Root)
							graph.AddEdge(nsStartNode, rootNode, "Query root server for NS IP (answer section)")
							// Set root server zone (root zone: ".")
							graph.SetNodeZone(domain, rootIP, dns.TypeAAAA, ".")
							// Recursively resolve NS IP using root server
							d.Resolver(ns.NameServer, dns.TypeA, rootIP, graph, cache, &nsIPs)
							// Associate root IP with its corresponding NS domain
							graph.SetNodeNameServer(ns.NameServer, rootIP, dns.TypeAAAA, rootNS)
						}
					default:
						for rootIP, rootNS := range RootServersv4 {
							// Add root server node to the graph
							rootNode := graph.AddNode(ns.NameServer, rootIP, dns.TypeA, Graph.Root)
							graph.AddEdge(nsStartNode, rootNode, "Query root server for NS IP (answer section)")
							// Set root server zone (root zone: ".")
							graph.SetNodeZone(domain, rootIP, dns.TypeA, ".")
							// Recursively resolve NS IP using root server
							d.Resolver(ns.NameServer, dns.TypeA, rootIP, graph, cache, &nsIPs)
							// Associate root IP with its corresponding NS domain
							graph.SetNodeNameServer(ns.NameServer, rootIP, dns.TypeA, rootNS)
						}
					}

					// Deduplicate and add resolved NS IPs to glue records
					for _, ipStr := range UniqueIPs(nsIPs) {
						ip := net.ParseIP(ipStr)
						if ip == nil {
							fmt.Printf("Invalid IP address for NS %s: %s\n", ns.NameServer, ipStr)
							continue
						}
						// Classify IP version and add to glue records
						if ip.To4() != nil {
							ns.IPv4GlueIPs = append(ns.IPv4GlueIPs, ip)
						} else {
							ns.IPv6GlueIPs = append(ns.IPv6GlueIPs, ip)
						}
					}

					// Build graph edges between NS IP nodes and domain resolution nodes
					for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
						var recordType uint16
						if ip.To4() != nil {
							recordType = dns.TypeA
						} else {
							recordType = dns.TypeAAAA
						}
						// Get NS IP node and add domain IP node
						nsIPNode, _ := graph.GetNodeID(ns.NameServer, ip.String(), recordType)
						domainIPNode := graph.AddNode(domain, ip.String(), recordType, Graph.Common)
						graph.AddEdge(nsIPNode, domainIPNode, "NS IP resolved (answer section)")
					}

					// Recursively resolve original domain using NS glue IPs
					for _, ip := range append(ns.IPv4GlueIPs, ns.IPv6GlueIPs...) {
						d.Resolver(domain, dns.TypeA, ip.String(), graph, cache, GetIP)
					}

					// Cache the NS records
					cache.AddRecord(domain, server, dns.TypeA, package2.NSRecords)
				}
			}
		}
	}

	return nil, nil
}