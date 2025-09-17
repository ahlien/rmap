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
	"net"
	"time"

	"github.com/miekg/dns"
)

// ExchangeStatus represents the result status of a DNS exchange operation
type ExchangeStatus int

// Constants defining different DNS exchange statuses
const (
	Normal       ExchangeStatus = iota // Normal successful exchange
	Timeout                            // Exchange timed out
	TxIDMismatch                       // Transaction ID mismatch between request and response
	Failure                            // Exchange failed (not due to timeout)
)

// NewMsg creates and returns a new DNS query message for the specified domain and record type
func NewMsg(recordType uint16, domain string) *dns.Msg {
	return buildPacket(recordType, domain)
}

// buildPacket constructs a standard DNS query packet with EDNS0 support
func buildPacket(recordType uint16, domain string) *dns.Msg {
	// Convert domain to fully qualified domain name (FQDN)
	fqdnDomain := dns.Fqdn(domain)
	
	msg := new(dns.Msg)
	msg.Id = dns.Id() // Generate random 16-bit transaction ID
	msg.RecursionDesired = true // Enable recursion request
	msg.Question = make([]dns.Question, 1)
	
	// Set up DNS question section
	msg.Question[0] = dns.Question{
		Name:   fqdnDomain,
		Qtype:  recordType,
		Qclass: dns.ClassINET, // Internet class (IPv4/IPv6)
	}
	
	// Enable EDNS0 (Extension Mechanisms for DNS) with 4096-byte UDP payload
	// false = disable DNSSEC support (set to true if DNSSEC validation is needed)
	msg.SetEdns0(4096, false)
	
	return msg
}

// Exchange sends a DNS message to the configured server and handles retries
// Returns the DNS response and exchange status
func (d *Rmap) Exchange(msg *dns.Msg) (*dns.Msg, ExchangeStatus) {
	var response *dns.Msg
	var status ExchangeStatus
	
	// Get retry count (default: 2 retries) and execute exchange with retries
	retryCount := d.SetRetry(2)
	for i := 0; i < retryCount; i++ {
		response, status = d.singleExchange(msg)
		// fmt.Println(response,status)
		
		// Return immediately if exchange is successful or irrecoverable (timeout/failure)
		if status != Normal {
			return response, status
		}
		
		// Short delay before next retry (100ms)
		time.Sleep(time.Second / 10)
	}


	
	// All retries completed successfully
	return response, Normal
}

// singleExchange performs a single DNS transaction without retries.
// It handles low-level network communication and basic error classification.
func (d *Rmap) singleExchange(msg *dns.Msg) (*dns.Msg, ExchangeStatus) {
    // Determine network protocol based on the configured Protocol (default: UDP)
    network := "udp"
    if d.Protocol == "tcp" {
        network = "tcp"
    }

    // Initialize the DNS client
    client := &dns.Client{
        Net:     network,   // TCP or UDP
        UDPSize: 4096,      // EDNS0-compliant UDP payload size
        Timeout: d.readTimeout(),
    }

    // Send the DNS query to the target server (RemoteAddr)
    response, _, err := client.Exchange(msg, d.RemoteAddr)

    if err != nil {
        // Classify the error type: timeout or general failure
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            return nil, Timeout
        }
        return nil, Failure
    }

    // Validate the transaction ID to prevent response spoofing
    if response.Id != msg.Id {
        return response, TxIDMismatch
    }

    return response, Normal
}

// GetMsg constructs a DNS query for the specified domain/type and returns the response
// Combines packet building and exchange logic into a single method
func (d *Rmap) GetMsg(recordType uint16, domain string) (*dns.Msg, ExchangeStatus) {
	msg := buildPacket(recordType, domain)
	return d.Exchange(msg)
}

