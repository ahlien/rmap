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



// Assist module: classify errors and handle DNS resolution tasks.
package Assist

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"rmap/pkg/Cache"
	"rmap/pkg/Graph"
	"rmap/pkg/Resolver"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// boolToStr converts a boolean to "1" or "0".
func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}


// domainWorker defines the function signature for processing a single domain
type domainWorker func(domain string, rmap *Resolver.Rmap)



// intToStr converts an integer to string.
func intToStr(i int) string {
	return strconv.Itoa(i)
}

// anyToStr converts a reflect.Value to string based on type.
func anyToStr(value reflect.Value) string {
	if value.Kind() == reflect.Bool {
		return boolToStr(value.Bool())
	}
	return intToStr(int(value.Int()))
}

// writeErrorsToCSV writes DNS errors for a domain to a CSV file and updates counters.
func writeErrorsToCSV(domain string, cache Cache.DNSCache, fileName string, mutex *sync.Mutex, errorCounters map[string]int) {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if empty
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("Error getting file info: %v\n", err)
		return
	}

	if fileInfo.Size() == 0 {
		header := []string{"domain"}
		e := reflect.ValueOf(&cache.Errors).Elem()
		for i := 0; i < e.NumField(); i++ {
			header = append(header, e.Type().Field(i).Name)
		}
		_ = writer.Write(header)
	}

	// Write record
	record := []string{domain}
	e := reflect.ValueOf(cache.Errors)
	for i := 0; i < e.NumField(); i++ {
		record = append(record, anyToStr(e.Field(i)))
	}
	_ = writer.Write(record)

	updateErrorCounters(cache.Errors, errorCounters)
}

// updateErrorCounters increments counters for error types.
func updateErrorCounters(errors Cache.ERROR, errorCounters map[string]int) {
	v := reflect.ValueOf(errors)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if v.Field(i).Bool() {
			errorCounters[field.Name]++
		}
	}
}

// writeStatisticsToCSV writes aggregated error statistics to a CSV file.
func writeStatisticsToCSV(fileName string, mutex *sync.Mutex, errorCounters map[string]int) {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{"ErrorType Count:"})
	for errorType, count := range errorCounters {
		_ = writer.Write([]string{errorType, strconv.Itoa(count)})
	}
}

// handleGraphAndCache processes the graph and cache, and stores JSON output.
func handleGraphAndCache(domain string, gg *Graph.DNSGraph, cc *Cache.DNSCache) {
	fmt.Println(gg.HasSelfLoop())

	gg.AssignLevels()
	jsonData := gg.ToJSON()

	storePath := filepath.Join(".", "pkg", "visual", "store")
	if err := os.MkdirAll(storePath, os.ModePerm); err != nil {
		panic(err)
	}

	domainName := strings.ReplaceAll(domain, ".", "_")
	jsonFile := filepath.Join(storePath, fmt.Sprintf("%s.json", domainName))
	writeToFile(jsonFile, jsonData)

	fmt.Println("Graph JSON has been written to", jsonFile)

	_ = cc.SaveCacheToJSON(storePath)
}

// writeToFile saves string data to a file.
func writeToFile(filePath string, data string) {
	file, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	if _, err = file.WriteString(data); err != nil {
		panic(err)
	}
}

// -----------------------------------------------------------------------------
// Generic Domain List Processor
// -----------------------------------------------------------------------------



// processDomainList is the unified entry point for processing a list of domains.
// It reads the domains line by line from the file and dispatches them to the worker concurrently.
func processDomainList(rmap *Resolver.Rmap, worker domainWorker) {
    // 1. Open the domain list file
    file, err := os.Open(rmap.DomainListFile)
    if err != nil {
        fmt.Printf("Error opening file: %v\n", err)
        os.Exit(1)
    }
    defer file.Close()

    // 2. Initialize scanner, WaitGroup, and concurrency semaphore
    scanner := bufio.NewScanner(file)
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, rmap.PoolSize) // controls concurrency
    startTime := time.Now()
    var domainCount int
    milestone := 10000
    milestoneTime := startTime

    // 3. Read domains line by line and dispatch to worker
    for scanner.Scan() {
        domain := scanner.Text()
        domainCount++

        // Acquire semaphore before starting a goroutine
        semaphore <- struct{}{}
        wg.Add(1)

        go func(domain string) {
            defer wg.Done()
            defer func() { <-semaphore }() // release semaphore upon completion

            // Clone rmap to ensure each goroutine operates independently
            rCopy := rmap.Clone() // implement Clone method in Rmap
            rCopy.Cache = Cache.NewDNSCache(domain, rCopy.IPversion)
            rCopy.Graph = Graph.NewGraph(domain)

            // Execute worker with independent rCopy
            worker(domain, rCopy)
        }(domain)

        // Log progress at milestones
        if domainCount%milestone == 0 {
            currentTime := time.Now()
            fmt.Printf("Resolved %d domains in %v\n", domainCount, currentTime.Sub(milestoneTime))
            milestoneTime = currentTime
        }
    }

    // 4. Check for scanning errors
    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        os.Exit(1)
    }

    // 5. Wait for all goroutines to finish
    wg.Wait()

    // 6. Print total execution time
    totalTime := time.Since(startTime)
    fmt.Printf("All domains resolved in %v\n", totalTime)
}




// HandleDomainList handles batch domain processing based on the Rmap structure
func HandleDomainList(rmap *Resolver.Rmap) {
    // 1. Validate protocol
    if rmap.Protocol != "tcp" && rmap.Protocol != "udp" {
        fmt.Printf("Error: Unsupported protocol '%s'. Use 'tcp' or 'udp'\n", rmap.Protocol)
        os.Exit(1)
    }

    // 2. Ensure error counters and mutex are initialized
    if rmap.ErrorCounters == nil {
        rmap.ErrorCounters = make(map[string]int)
    }
    if rmap.Mutex == nil {
        rmap.Mutex = &sync.Mutex{}
    }

    // 3. Dispatch according to operation mode
    switch rmap.Mode {
    case 2: // JSON output mode
        worker := func(domain string, r *Resolver.Rmap) {
            cc := Cache.NewDNSCache(domain, r.IPversion)
            gg := Graph.NewGraph(domain)
            r.Trace(domain, dns.TypeA, gg, cc, r.Mutex, 0)
            handleGraphAndCache(domain, gg, cc)
        }
        processDomainList(rmap, worker)

    case 3: // CSV error output mode
        worker := func(domain string, r *Resolver.Rmap) {
            cc := Cache.NewDNSCache(domain, r.IPversion)
            gg := Graph.NewGraph(domain)
            r.Trace(domain, dns.TypeA, gg, cc, r.Mutex, 0)
            writeErrorsToCSV(domain, *cc, r.OutputFile, r.Mutex, r.ErrorCounters)
        }
        processDomainList(rmap, worker)
        writeStatisticsToCSV(rmap.OutputFile, rmap.Mutex, rmap.ErrorCounters)

    case 4, 5, 6, 7, 8, 9: // Authority/NS modes
        worker := func(domain string, r *Resolver.Rmap) {
            cc := Cache.NewDNSCache(domain, r.IPversion)
            gg := Graph.NewGraph(domain)
            r.Trace(domain, dns.TypeA, gg, cc, r.Mutex, r.Mode)
            writeErrorsToCSV(domain, *cc, r.OutputFile, r.Mutex, r.ErrorCounters)
        }
        processDomainList(rmap, worker)

    default:
        fmt.Printf("Error: Invalid mode %d\n", rmap.Mode)
        os.Exit(1)
    }
}



// -----------------------------------------------------------------------------
// Mode Handlers
// -----------------------------------------------------------------------------



// func HandleSingleDomain(rmap *Resolver.Rmap) {
//     // 1. Read configuration from Rmap and validate protocol
//     if rmap.Protocol != "tcp" && rmap.Protocol != "udp" {
//         fmt.Printf("Error: Unsupported protocol '%s'. Use 'tcp' or 'udp'\n", rmap.Protocol)
//         os.Exit(1)
//     }

//     // 2. Validate operation mode (read from Rmap)
//     fmt.Printf("Processing single domain: %s (Protocol: %s)\n", rmap.Domain, rmap.Protocol)
//     switch rmap.Mode {
//     case 1, 2, 3, 4, 5, 6, 7, 8, 9:
        
        
//         // 3. Ensure Cache/Graph are initialized (create if nil to avoid panic)
//         if rmap.Cache == nil {
//             rmap.Cache = Cache.NewDNSCache(rmap.Domain, rmap.IPversion)
//         }
//         if rmap.Graph == nil {
//             rmap.Graph = Graph.NewGraph(rmap.Domain)
//         }

//         // // 4. Call the processing function, passing the Rmap instance
//         // processSingleDomainMod3(rmap)



//     default:
//         fmt.Printf("Error: Invalid mode %d\n", rmap.Mode)
//         os.Exit(1)
//     }
// }


// HandleSingleDomain processes a single domain using Rmap, following batch-processing logic
func HandleSingleDomain(rmap *Resolver.Rmap) {
    // 1. Validate protocol
    if rmap.Protocol != "tcp" && rmap.Protocol != "udp" {
        fmt.Printf("Error: Unsupported protocol '%s'. Use 'tcp' or 'udp'\n", rmap.Protocol)
        os.Exit(1)
    }

    // 2. Ensure error counters and mutex are initialized
    if rmap.ErrorCounters == nil {
        rmap.ErrorCounters = make(map[string]int)
    }
    if rmap.Mutex == nil {
        rmap.Mutex = &sync.Mutex{}
    }

    // 3. Initialize Cache and Graph for the single domain
    if rmap.Cache == nil {
        rmap.Cache = Cache.NewDNSCache(rmap.Domain, rmap.IPversion)
    }
    if rmap.Graph == nil {
        rmap.Graph = Graph.NewGraph(rmap.Domain)
    }

    // 4. Dispatch according to operation mode
    switch rmap.Mode {
    case 2: // JSON output mode
        rmap.Trace(rmap.Domain, dns.TypeA, rmap.Graph, rmap.Cache, rmap.Mutex, 0)
        handleGraphAndCache(rmap.Domain, rmap.Graph, rmap.Cache)

    case 3: // CSV error output mode
        rmap.Trace(rmap.Domain, dns.TypeA, rmap.Graph, rmap.Cache, rmap.Mutex, 0)
        writeErrorsToCSV(rmap.Domain, *rmap.Cache, rmap.OutputFile, rmap.Mutex, rmap.ErrorCounters)
        writeStatisticsToCSV(rmap.OutputFile, rmap.Mutex, rmap.ErrorCounters)

    case 4, 5, 6, 7, 8, 9: // Authority/NS modes
        rmap.Trace(rmap.Domain, dns.TypeA, rmap.Graph, rmap.Cache, rmap.Mutex, rmap.Mode)
        writeErrorsToCSV(rmap.Domain, *rmap.Cache, rmap.OutputFile, rmap.Mutex, rmap.ErrorCounters)

    default:
        fmt.Printf("Error: Invalid mode %d\n", rmap.Mode)
        os.Exit(1)
    }
}



// -----------------------------------------------------------------------------
// Single Domain Helpers
// -----------------------------------------------------------------------------

// processSingleDomain handles a single domain and generates JSON.
func processSingleDomain(domain string, version int) {
	startTime := time.Now()
	cc := Cache.NewDNSCache(domain, version)
	gg := Graph.NewGraph(domain)

	handleGraphAndCache(domain, gg, cc)

	fmt.Printf("Domain %s resolved in %v\n", domain, time.Since(startTime))
}




// processSingleDomainMod3 processes a single domain based on the Rmap structure, performing DNS resolution and error categorization
// Input: rmap - a unified configuration and resource management instance (core fields such as Domain, IPversion, Mode, OutputFile must be pre-initialized)
func processSingleDomainMod3(rmap *Resolver.Rmap) {
    // 1. Record the start time of resolution (preserve original logic)
    startTime := time.Now()

    // 2. Reuse resources from Rmap: initialize if nil to avoid redundant creation and nil dereference
    // - Cache: bind to the current domain and IP version
    if rmap.Cache == nil {
        rmap.Cache = Cache.NewDNSCache(rmap.Domain, rmap.IPversion)
    }
    // - Graph: bind to the current domain
    if rmap.Graph == nil {
        rmap.Graph = Graph.NewGraph(rmap.Domain)
    }
    // - ErrorCounters: reuse global error statistics to facilitate aggregation
    if rmap.ErrorCounters == nil {
        rmap.ErrorCounters = make(map[string]int)
    }
    // - Mutex: reuse Rmap lock to ensure concurrency safety (maintains consistency with batch processing scenarios)
    if rmap.Mutex == nil {
        rmap.Mutex = &sync.Mutex{}
    }

    // 3. Execute DNS resolution by invoking Rmap.Trace, directly reusing resources and configuration in the struct
    // No longer pass individual parameters such as domain/version/mode; read from rmap
    rmap.Trace(
        rmap.Domain,   
        dns.TypeA,     
        rmap.Graph,     
        rmap.Cache,    
        rmap.Mutex,     
        rmap.Mode,     
    )

    // 4. Write error data to CSV, reusing Rmap output path, cache, mutex, and error statistics
    // Default output file is "dns_errors.csv" if Rmap.OutputFile is not specified
    outputFile := rmap.OutputFile
    if outputFile == "" {
        outputFile = "dns_errors.csv"
    }
    writeErrorsToCSV(
        rmap.Domain,        
        *rmap.Cache,       
        outputFile,         
        rmap.Mutex,         
        rmap.ErrorCounters,  
    )

    // 5. Print resolution duration (preserve original logic, reading domain from Rmap)
    fmt.Printf("Domain %s resolved in %v\n", rmap.Domain, time.Since(startTime))

    // 6. Write statistical data to CSV, reusing Rmap resources and maintaining consistency with error logging
    writeStatisticsToCSV(
        outputFile,          
        rmap.Mutex,          
        rmap.ErrorCounters,  
    )
}
