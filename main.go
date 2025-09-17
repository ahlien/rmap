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
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"sync"
	"rmap/Assist"
	"rmap/pkg/Cache"
	"rmap/pkg/Graph"
	"rmap/pkg/Resolver" 
)

func main() {
	// Parse command-line arguments
	domain := flag.String("d", "", "Single domain input (e.g., example.com)")
	domainListFile := flag.String("l", "", "Path to a file containing a list of domains (one per line)")
	poolSizeStr := flag.String("p", "", "Worker pool size (must be a positive integer)")
	mod := flag.Int("mod", 0, "Operation mode (required):\n"+
		"  1 = Todo functionality\n"+
		"  2 = Generate JSON output file. Located in pkg/visual/store/\n"+
		"  3 = Identify domain names misconfigurations\n"+
		"  4 = All corresponding IP addresses\n"+
		"  5 = All nameservers\n"+
		"  6 = All AAAA (IPv6) records\n"+
		"  7 = The full-resolution topology\n"+
		"  8 = All IPv6 nameservers\n"+
		"  9 = Detect DNS resolution cycles")
	outputFile := flag.String("output", "", "Path for output CSV file (default depends on -d or -l)")
	ipVersion := flag.Int("v", 0, "IP version to use:\n"+
		"  4 = IPv4 only\n"+
		"  6 = IPv6 only\n"+
		"  0 = Dual-stack (IPv4 + IPv6, default)")
	protocol := flag.String("proto", "udp", "Network protocol for DNS queries:\n"+
		"  tcp = Use TCP (for large responses)\n"+
		"  udp = Use UDP (default, faster for most cases)")

	flag.Parse()

	// Validation: either -d or -l must be provided
	if *domain == "" && *domainListFile == "" {
		fmt.Printf("Error: must set either -d <domain> or -l <domainListFile>\n\n")
		flag.Usage()
		os.Exit(1)
	}
	if *domain != "" && *domainListFile != "" {
		fmt.Printf("Error: cannot set both -d and -l; choose one\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Validate operation mode
	if *mod == 0 || *mod < 1 || *mod > 9 {
		fmt.Printf("Error: -mod must be set to a value between 1–9\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Parse worker pool size
	poolSize := 0
	if *poolSizeStr != "" {
		var err error
		poolSize, err = strconv.Atoi(*poolSizeStr)
		if err != nil || poolSize <= 0 {
			fmt.Printf("Error: Invalid worker pool size '%s' — must be a positive integer\n", *poolSizeStr)
			os.Exit(1)
		}
	} else {
		// Set default pool size based on single/batch mode
		if *domain != "" {
			poolSize = 1
		} else {
			poolSize = 100
		}
	}

	// Set default output file path
	outputPath := *outputFile
	if outputPath == "" {
		if *domain != "" {
			outputPath = "domain.csv"
		} else {
			base := filepath.Base(*domainListFile)
			name := strings.TrimSuffix(base, filepath.Ext(base))
			outputPath = name + ".csv"
		}
	}

	// Validate protocol type
	if *protocol != "tcp" && *protocol != "udp" {
		fmt.Printf("Error: Invalid protocol '%s' — only 'tcp' or 'udp' are supported\n", *protocol)
		os.Exit(1)
	}

	// Initialize Rmap struct to manage all configuration parameters
	rmap := &Resolver.Rmap{
		Domain:         *domain,
		DomainListFile: *domainListFile,
		PoolSize:       poolSize,
		Mode:           *mod,
		OutputFile:     outputPath,
		IPversion:      *ipVersion,
		Protocol:       *protocol,
		// Default timeout settings (5 seconds)
		DialTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
		// Default retry attempts
		Retry: 2,
		// Shared concurrency-safe resources
		ErrorCounters: make(map[string]int),
		Mutex:         &sync.Mutex{},
	}

	// Execute based on input type
	if *domain != "" {
		// Single domain: initialize cache and graph (domain-specific)
		rmap.Cache = Cache.NewDNSCache(*domain, *ipVersion)
		rmap.Graph = Graph.NewGraph(*domain)
		Assist.HandleSingleDomain(rmap)
	} else {
		// Domain list: each worker initializes its own cache and graph
		Assist.HandleDomainList(rmap)
	}
}
