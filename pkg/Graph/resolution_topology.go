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


 
package Graph

import (
	"encoding/json"
	"fmt"
	"sync"
)

// NodeType represents the classification of a DNS graph node, indicating specific
// DNS resolution states, errors, or record types. Values map to common DNS outcomes
// and protocol-specific states.
type NodeType int

// Predefined NodeType values covering DNS resolution outcomes, errors, and record types.
// Aligned with DNS RCODEs (RFC 1035) and custom resolution states for comprehensive tracking.
const (
	Begin NodeType = iota // 0: Initial starting node of the resolution process
	FormErr               // 1: Malformed DNS query/response (invalid packet structure)
	ServerFailure         // 2: DNS server reported failure (RCODE 2)
	NXDOMAIN              // 3: Non-existent domain (RCODE 3)
	NotImplemented        // 4: DNS operation not implemented (RCODE 4)
	Refused               // 5: DNS server refused the query (RCODE 5)
	Timeout               // 6: DNS query timed out (no response received)
	NoNsRecord            // 7: No nameserver (NS) records found for domain
	NsNotGlueIP           // 8: Nameserver lacks glue IP address (cannot resolve NS hostname)
	IPError               // 9: Invalid or unreachable IP address (e.g., private IP in public context)
	IDMisMatch            // 10: DNS query/response ID mismatch (potential spoofing)
	LeaveA                // 11: Resolution path terminates with A (IPv4) record
	LeaveAAAA             // 12: Resolution path terminates with AAAA (IPv6) record
	LeaveCNAME            // 13: Resolution path terminates with CNAME record
	SOA                   // 14: Start of Authority (SOA) record encountered
	Hijack                // 15: Potential DNS hijacking detected (unexpected response)
	Common                // 16: Common intermediate resolution node (generic step)
	NsInAnswer            // 17: Nameserver records present in answer section (non-standard)
	PacketErr             // 18: Invalid DNS packet (corrupt data, invalid fields)
	YXDomain              // 19: Domain already exists (RCODE 6, used in dynamic updates)
	Root                  // 20: Root DNS server node (top-level of DNS hierarchy)
	NonRoutableIP         // 21: Non-routable IP address (e.g., 192.168.0.0/16 in public response)
	YXRRSet               // 22: RRSet already exists (RCODE 7, dynamic updates)
	NXRRSet               // 23: RRSet does not exist (RCODE 8, dynamic updates)
	NotAuthorized         // 24: Server not authorized for domain (RCODE 9)
	NotInZone             // 25: Record not in authoritative zone (RCODE 10)
	ExchangeFailure
)

// nodeTypeStrings provides human-readable string representations for each NodeType.
// Must maintain 1:1 order with the NodeType constant definitions above.
var nodeTypeStrings = []string{
	"Begin",
	"FormErr",
	"ServerFailure",
	"NXDOMAIN",
	"NotImplemented",
	"Refused",
	"Timeout",
	"NoNsRecord",
	"NsNotGlueIP",
	"IPError",
	"IDMisMatch",
	"LeaveA",
	"LeaveAAAA",
	"LeaveCNAME",
	"SOA",
	"Hijack",
	"Common",
	"NsInAnswer",
	"PacketErr",
	"YXDomain",
	"Root",
	"NonRoutableIP",
	"YXRRSet",
	"NXRRSet",
	"NotAuthorized",
	"NotInZone",
}

// Node represents a single entity in the DNS resolution graph, capturing
// details about a specific DNS query/response pair. Each node is uniquely
// identified by the combination of Domain, IP, and QType.
type Node struct {
	Domain     string   `json:"domain"`     // Domain name being resolved (e.g., "example.com")
	IP         string   `json:"ip"`         // IP address associated with this node (empty for non-IP steps)
	QType      uint16   `json:"qType"`      // DNS query type (e.g., 1 for A, 28 for AAAA; RFC 1035)
	NameServer string   `json:"nameServer"` // Nameserver used for this resolution step (empty if none)
	Zone       string   `json:"zone"`       // DNS zone for this node (e.g., "com." for example.com)
	NodeID     int      `json:"nodeID"`     // Unique identifier for this node (auto-assigned)
	NodeType   NodeType `json:"nodeType"`   // Classification of this node (resolution state/error)
	Level      int      `json:"level"`      // Hierarchy level in the resolution tree (-1 = unassigned)
	IsVisit    bool     `json:"isVisit"`    // Flag indicating if node has been processed (for traversal)
}

// Edge represents a directed relationship between two nodes in the graph,
// indicating a dependency in the DNS resolution process (e.g., "query A requires query B").
type Edge struct {
	FromNodeID int    `json:"fromNodeID"` // ID of the source node (dependency origin)
	ToNodeID   int    `json:"toNodeID"`   // ID of the target node (dependency target)
	Label      string `json:"label"`      // Optional description of the relationship (e.g., "NS lookup")
}

// DNSGraph represents a complete DNS resolution dependency graph for a specific domain,
// containing all nodes, edges, and metadata about the resolution process.
type DNSGraph struct {
	Nodes  map[string]Node // Mapping of nodes by composite key (domain|ip|qtype)
	Edges  map[string]Edge // Mapping of edges by composite key (fromNodeID-toNodeID)
	nextID int             // Next available unique node ID (auto-increments)
	Domain string          // Target domain for this resolution graph (e.g., "example.com")
}

// DNSGraphCollection manages a set of DNSGraph instances, providing thread-safe
// access and management of multiple resolution graphs (e.g., for batch processing).
type DNSGraphCollection struct {
	Graphs map[string]*DNSGraph // Mapping of graphs by domain name (unique key)
	mu     sync.Mutex           // Mutex for thread-safe operations on the collection
}

// MarshalJSON implements the json.Marshaler interface for NodeType,
// converting NodeType constants to human-readable strings in JSON output.
// Returns an error if the NodeType value is out of valid range.
func (nt NodeType) MarshalJSON() ([]byte, error) {
	if int(nt) < 0 || int(nt) >= len(nodeTypeStrings) {
		return nil, fmt.Errorf("invalid NodeType: %d (valid range: 0-%d)", nt, len(nodeTypeStrings)-1)
	}
	return json.Marshal(nodeTypeStrings[nt])
}

// nodeKey generates a unique composite key for identifying nodes based on their
// Domain, IP, and QType. Ensures no duplicate nodes for identical resolution steps.
func nodeKey(domain, ip string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%d", domain, ip, qtype)
}

// edgeKey generates a unique composite key for identifying edges based on their
// source (FromNodeID) and target (ToNodeID) node IDs. Prevents duplicate edges.
func edgeKey(fromNodeID, toNodeID int) string {
	return fmt.Sprintf("%d-%d", fromNodeID, toNodeID)
}

// NewGraph initializes and returns a new DNSGraph instance for the specified domain.
// Sets up empty node/edge maps and initializes the next node ID to 1 (0 = invalid).
func NewGraph(domain string) *DNSGraph {
	return &DNSGraph{
		Nodes:  make(map[string]Node),
		Edges:  make(map[string]Edge),
		nextID: 1,
		Domain: domain,
	}
}

// NewDNSGraphCollection initializes and returns a new thread-safe collection
// for managing multiple DNSGraph instances. Ideal for batch processing of domains.
func NewDNSGraphCollection() *DNSGraphCollection {
	return &DNSGraphCollection{
		Graphs: make(map[string]*DNSGraph),
	}
}

// IsNodeVisited checks if a node with the specified Domain, IP, and QType has been
// marked as visited (via the IsVisit flag). Returns false if the node does not exist.
func (g *DNSGraph) IsNodeVisited(domain, ip string, qtype uint16) bool {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if !exists {
		return false
	}
	return node.IsVisit
}

// MarkNodeVisited marks a node with the specified Domain, IP, and QType as visited
// (sets IsVisit = true). Does nothing if the node does not exist.
func (g *DNSGraph) MarkNodeVisited(domain, ip string, qtype uint16) {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if !exists {
		return
	}
	node.IsVisit = true
	g.Nodes[key] = node
}

// AddNode adds a new node to the graph with the specified attributes. If a node with
// the same Domain, IP, and QType already exists, it updates the node's type (if different)
// and returns the existing node's ID. Returns the new node's ID if created.
func (g *DNSGraph) AddNode(domain, ip string, qType uint16, nodeType NodeType) int {
	key := nodeKey(domain, ip, qType)

	// Check for existing node
	if existingNode, exists := g.Nodes[key]; exists {
		// Update node type if it has changed
		if existingNode.NodeType != nodeType {
			existingNode.NodeType = nodeType
			g.Nodes[key] = existingNode
		}
		return existingNode.NodeID
	}

	// Create new node with auto-assigned ID
	nodeID := g.nextID
	g.nextID++

	newNode := Node{
		Domain:     domain,
		IP:         ip,
		QType:      qType,
		NodeID:     nodeID,
		NodeType:   nodeType,
		NameServer: "",
		Zone:       "",
		Level:      -1, // Unassigned by default
		IsVisit:    false,
	}

	g.Nodes[key] = newNode
	return nodeID
}

// SetNodeLevel sets the hierarchy level for a node with the specified Domain, IP, and QType.
// Does nothing if the node does not exist. Levels represent the depth in the resolution tree.
func (g *DNSGraph) SetNodeLevel(domain, ip string, qtype uint16, level int) {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if !exists {
		return
	}
	node.Level = level
	g.Nodes[key] = node
}

// SetNodeNameServer sets the Nameserver field for a node with the specified Domain, IP, and QType.
// Returns an error if the node does not exist. Useful for tracking which nameserver resolved a step.
func (g *DNSGraph) SetNodeNameServer(domain, ip string, qtype uint16, nameServer string) error {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if !exists {
		return fmt.Errorf("node not found (key: %s)", key)
	}

	node.NameServer = nameServer
	g.Nodes[key] = node
	return nil
}

// SetNodeZone sets the Zone field for a node with the specified Domain, IP, and QType.
// Returns an error if the node does not exist. Tracks the DNS zone for authoritative checks.
func (g *DNSGraph) SetNodeZone(domain, ip string, qtype uint16, zone string) error {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if !exists {
		return fmt.Errorf("node not found (key: %s)", key)
	}

	node.Zone = zone
	g.Nodes[key] = node
	return nil
}

// SetNodeType updates the NodeType of a node with the specified NodeID.
// Returns true if the node was found and updated, false otherwise.
func (g *DNSGraph) SetNodeType(nodeID int, nodeType NodeType) bool {
	for key, node := range g.Nodes {
		if node.NodeID == nodeID {
			node.NodeType = nodeType
			g.Nodes[key] = node
			return true
		}
	}
	return false
}

// GetNodeID retrieves the NodeID of a node with the specified Domain, IP, and QType.
// If the node does not exist, it creates a new node with NodeType = Begin and returns:
// - The new NodeID
// - A boolean = true (indicating the node was created)
// If the node exists, returns the existing NodeID and boolean = false.
func (g *DNSGraph) GetNodeID(domain, ip string, qtype uint16) (int, bool) {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]

	if exists {
		return node.NodeID, false
	}

	// Create new node with default type (Begin) if not found
	nodeID := g.AddNode(domain, ip, qtype, Begin)
	return nodeID, true
}

// GetNode retrieves a node with the specified Domain, IP, and QType.
// Returns:
// - The node (zero-value if not found)
// - A boolean = true if the node exists, false otherwise
func (g *DNSGraph) GetNode(domain, ip string, qtype uint16) (Node, bool) {
	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	return node, exists
}

// AddEdge adds a directed edge between two nodes (FromNodeID → ToNodeID) with an optional label.
// Does nothing if an edge between the same nodes already exists (prevents duplicates).
func (g *DNSGraph) AddEdge(fromNodeID, toNodeID int, label string) {
	key := edgeKey(fromNodeID, toNodeID)
	if _, exists := g.Edges[key]; exists {
		return
	}

	g.Edges[key] = Edge{
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
		Label:      label,
	}
}

// AssignLevels calculates and assigns hierarchy levels to all nodes using DFS.
// Starts from the "Begin" node (IP = "begin", Level = 0) and propagates levels
// to child nodes (Level = parent Level + 1). Ignores unconnected nodes.
func (g *DNSGraph) AssignLevels() {
	visited := make(map[int]bool)

	// Recursive DFS to assign levels
	var assignLevel func(nodeID, currentLevel int)
	assignLevel = func(nodeID, currentLevel int) {
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		// Update the node's level
		for key, node := range g.Nodes {
			if node.NodeID == nodeID {
				node.Level = currentLevel
				g.Nodes[key] = node
				break
			}
		}

		// Process all child nodes (outgoing edges)
		for _, edge := range g.Edges {
			if edge.FromNodeID == nodeID {
				assignLevel(edge.ToNodeID, currentLevel+1)
			}
		}
	}

	// Find the initial "Begin" node and start level assignment
	for _, node := range g.Nodes {
		if node.IP == "begin" && node.Level == 0 {
			assignLevel(node.NodeID, 0)
			break
		}
	}
}

// HasSelfLoop checks if the graph contains any self-loops (edges where FromNodeID == ToNodeID).
// Returns true if a self-loop exists, false otherwise. Self-loops indicate circular dependencies.
func (g *DNSGraph) HasSelfLoop() bool {
	for _, edge := range g.Edges {
		if edge.FromNodeID == edge.ToNodeID {
			return true
		}
	}
	return false
}


// HasCycle checks if the graph contains any cycles (self-loops or multi-node cycles).
// Uses DFS to detect multi-node cycles; returns true immediately if a self-loop is found (fast path).
func (g *DNSGraph) HasCycle() bool {
	// Fast path: check for self-loops first
	if g.HasSelfLoop() {
		return true
	}

	// Check for multi-node cycles using DFS
	visited := make(map[int]bool)
	recursionStack := make(map[int]bool)

	for _, node := range g.Nodes {
		if !visited[node.NodeID] && g.hasCycleDFS(node.NodeID, visited, recursionStack) {
			return true
		}
	}
	return false
}

// hasCycleDFS is a helper function that uses depth-first search to detect cycles.
// It tracks visited nodes and current recursion stack to identify back edges.
func (g *DNSGraph) hasCycleDFS(nodeID int, visited, recursionStack map[int]bool) bool {
	visited[nodeID] = true
	recursionStack[nodeID] = true

	// Check all outgoing edges from current node
	for _, edge := range g.Edges {
		if edge.FromNodeID == nodeID {
			targetID := edge.ToNodeID
			
			if !visited[targetID] {
				if g.hasCycleDFS(targetID, visited, recursionStack) {
					return true
				}
			} else if recursionStack[targetID] {
				// Found back edge to node in current recursion stack - cycle detected
				return true
			}
		}
	}

	// Remove from recursion stack when backtracking
	recursionStack[nodeID] = false
	return false
}

// FindAllCycles discovers and returns all cycles in the graph. Each cycle is represented
// as a slice of node IDs in traversal order. Self-loops are included as single-element slices.
func (g *DNSGraph) FindAllCycles() [][]int {
	var cycles [][]int
	visited := make(map[int]bool)

	// Check each unvisited node for cycles
	for _, node := range g.Nodes {
		if !visited[node.NodeID] {
			var recursionStack []int
			g.findAllCyclesDFS(node.NodeID, visited, recursionStack, &cycles)
		}
	}

	return cycles
}

// findAllCyclesDFS is a helper function that uses DFS to find all cycles.
// It builds and tracks the recursion stack to identify and extract complete cycles.
func (g *DNSGraph) findAllCyclesDFS(
	nodeID int,
	visited map[int]bool,
	recursionStack []int,
	cycles *[][]int,
) {
	visited[nodeID] = true
	recursionStack = append(recursionStack, nodeID)

	// Check all outgoing edges
	for _, edge := range g.Edges {
		if edge.FromNodeID == nodeID {
			targetID := edge.ToNodeID
			
			// Check if target is in current recursion stack (indicating a cycle)
			if idx := indexOf(recursionStack, targetID); idx != -1 {
				// Extract the cycle from the stack (from target index to end)
				cycle := make([]int, len(recursionStack)-idx)
				copy(cycle, recursionStack[idx:])
				*cycles = append(*cycles, cycle)
			} else if !visited[targetID] {
				// Continue DFS if target hasn't been visited
				g.findAllCyclesDFS(targetID, visited, recursionStack, cycles)
			}
		}
	}

	// Remove current node from recursion stack when backtracking
	recursionStack = recursionStack[:len(recursionStack)-1]
}

// GetCycleStats analyzes all cycles in the graph and returns statistics:
// - Number of self-loops (1-node cycles)
// - Number of multi-node cycles (2+ nodes)
// - Size of the largest cycle
// - Size of the smallest cycle (-1 if no cycles)
func (g *DNSGraph) GetCycleStats() (int, int, int, int) {
	cycles := g.FindAllCycles()
	if len(cycles) == 0 {
		return 0, 0, 0, -1
	}

	selfLoops := 0
	multiNodeCycles := 0
	maxSize := 0
	minSize := len(cycles[0])

	for _, cycle := range cycles {
		cycleSize := len(cycle)
		
		if cycleSize == 1 {
			selfLoops++
		} else {
			multiNodeCycles++
			
			if cycleSize > maxSize {
				maxSize = cycleSize
			}
			if cycleSize < minSize {
				minSize = cycleSize
			}
		}
	}

	// Handle case where there are only self-loops
	if multiNodeCycles == 0 {
		maxSize = 0
		minSize = 0
	}

	return selfLoops, multiNodeCycles, maxSize, minSize
}

// GetGraph retrieves a DNSGraph for the specified domain from the collection.
// Returns the graph and a boolean indicating if the graph exists.
// Thread-safe implementation using a mutex.
func (d *DNSGraphCollection) GetGraph(domain string) (*DNSGraph, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	graph, exists := d.Graphs[domain]
	return graph, exists
}

// AddGraph adds a DNSGraph to the collection. If a graph for the same domain
// already exists, it will be overwritten. Thread-safe implementation.
func (d *DNSGraphCollection) AddGraph(graph *DNSGraph) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Graphs[graph.Domain] = graph
}

// QTypeToString converts a DNS query type (QType) numeric value to its
// human-readable string representation (e.g., 1 → "A", 28 → "AAAA").
// Returns "Unknown(n)" for unrecognized types.
func QTypeToString(qType uint16) string {
	qTypeMap := map[uint16]string{
		1:  "A",     // IPv4 address
		2:  "NS",    // Nameserver
		5:  "CNAME", // Canonical name
		6:  "SOA",   // Start of authority
		12: "PTR",   // Pointer
		15: "MX",    // Mail exchange
		16: "TXT",   // Text record
		28: "AAAA",  // IPv6 address
		33: "SRV",   // Service locator
		43: "DS",    // Delegation signer
		46: "RRSIG", // DNSSEC signature
		50: "NSEC",  // Next secure record
		51: "DNSKEY", // DNSSEC key
	}

	if str, exists := qTypeMap[qType]; exists {
		return str
	}
	return fmt.Sprintf("Unknown(%d)", qType)
}

// ToJSON converts the graph to a pretty-printed JSON string containing
// all nodes and edges. Panics on JSON serialization error (for simplicity).
func (g *DNSGraph) ToJSON() string {
	// Create a temporary struct for clean JSON output
	data := struct {
		Domain string  `json:"domain"`
		Nodes  []Node  `json:"nodes"`
		Edges  []Edge  `json:"edges"`
	}{
		Domain: g.Domain,
		Nodes:  make([]Node, 0, len(g.Nodes)),
		Edges:  make([]Edge, 0, len(g.Edges)),
	}

	// Convert node map to slice
	for _, node := range g.Nodes {
		data.Nodes = append(data.Nodes, node)
	}

	// Convert edge map to slice
	for _, edge := range g.Edges {
		data.Edges = append(data.Edges, edge)
	}

	// Marshal with indentation for readability
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("JSON serialization failed: %v", err))
	}

	return string(jsonData)
}

// PrintNodes outputs all nodes in the graph to stdout with human-readable formatting.
func (g *DNSGraph) PrintNodes() {
	fmt.Println("Graph Nodes:")
	for _, node := range g.Nodes {
		fmt.Printf(
			"ID: %d, Domain: %s, IP: %s, QType: %s, Type: %s, Level: %d\n",
			node.NodeID,
			node.Domain,
			node.IP,
			QTypeToString(node.QType),
			nodeTypeStrings[node.NodeType],
			node.Level,
		)
	}
}

// PrintEdges outputs all edges in the graph to stdout with source → target formatting.
func (g *DNSGraph) PrintEdges() {
	fmt.Println("Graph Edges:")
	for _, edge := range g.Edges {
		if edge.Label != "" {
			fmt.Printf("%d -> %d [Label: %s]\n", edge.FromNodeID, edge.ToNodeID, edge.Label)
		} else {
			fmt.Printf("%d -> %d\n", edge.FromNodeID, edge.ToNodeID)
		}
	}
}

// PrintGraph outputs a compact representation of the graph, including
// edge relationships and node details for quick visual inspection.
func (g *DNSGraph) PrintGraph() {
	// Print edge summary
	fmt.Printf("Domain: %s", g.Domain)
	fmt.Println() 
	fmt.Printf("Edges: [")
	firstEdge := true
	for _, edge := range g.Edges {
		if !firstEdge {
			fmt.Print(", ")
		}
		fmt.Printf("%d>%d", edge.FromNodeID, edge.ToNodeID)
		firstEdge = false
	}
	fmt.Print("] ")
	fmt.Println() // add new line
	// Print node summary
	fmt.Print("Nodes: [")
	firstNode := true
	for _, node := range g.Nodes {
		if !firstNode {
			fmt.Print(", ")
		}
		fmt.Printf("%d(%s,%s,%s)",
			node.NodeID,
			node.Domain,
			node.IP,
			QTypeToString(node.QType),
		)
		firstNode = false
	}
	fmt.Println("]")
}

// PrintCycles outputs all detected cycles in the graph to stdout.
func (g *DNSGraph) PrintCycles() {
	cycles := g.FindAllCycles()
	if len(cycles) == 0 {
		fmt.Printf("No cycles detected in graph for domain: %s\n", g.Domain)
		return
	}

	fmt.Printf("Cycles detected in graph for domain: %s\n", g.Domain)
	for i, cycle := range cycles {
		fmt.Printf("Cycle %d: %v\n", i+1, cycle)
	}
}

// PrintGraphDetails outputs a comprehensive overview of the graph, including
// all nodes with full details, all edges, and cycle statistics.
func (g *DNSGraph) PrintGraphDetails() {
	fmt.Printf("=== DNS Resolution Graph for %s ===\n", g.Domain)
	fmt.Printf("Total nodes: %d\n", len(g.Nodes))
	fmt.Printf("Total edges: %d\n", len(g.Edges))
	
	selfLoops, multiCycles, maxCycle, minCycle := g.GetCycleStats()
	fmt.Printf("Cycle statistics: Self-loops=%d, Multi-node cycles=%d, Largest cycle=%d nodes, Smallest cycle=%d nodes\n",
		selfLoops, multiCycles, maxCycle, minCycle)
	
	g.PrintNodes()
	g.PrintEdges()
}

// indexOf returns the index of the first occurrence of target in the slice,
// or -1 if the target is not found. Helper function for cycle detection.
func indexOf(slice []int, target int) int {
	for i, val := range slice {
		if val == target {
			return i
		}
	}
	return -1
}