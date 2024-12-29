// 图模块，包含关于域名解析依赖拓扑图的所有设计、实现，可根据需求不断进行扩展
package Graph

import (
	"encoding/json"
	"fmt"
	"sync"
)

// NodeType 定义了DNS节点的类型，用整数表示
type NodeType int

// const (
// 	Begin          NodeType = iota // 0
// 	FormErr                        // 1
// 	Serverfailure                  // 2
// 	NXDOMAIN                       // 3
// 	NotImplemented                 // 4
// 	Refused                        // 5
// 	Timeout                        // 6
// 	NoNsrecord                     // 7
// 	NsNotGlueIP                    // 8
// 	IPerror                        // 9
// 	IDMisMatch                     // 10
// 	LeaveA                         // 11
// 	LeaveAAAA                      // 12
// 	LeaveCNAME                     // 13
// 	SOA                            // 14
// 	Hijack                         // 15
// 	Common                         // 16
// 	NsInAnswer                     // 17
// 	PacketErr                      // 18
// 	YXDomain                       // 19
// 	Root                           // 20
// 	NonRoutableIP                  // 21

// 	// YXRRSet
// 	// NXRRSet
// 	// NotZone
// 	// NotAuth
// 	// BadVersOrSig
// 	// BadKey
// 	// BadTime
// 	// BadMode
// 	// BadName
// 	// BadAlg
// 	// BadTrunc
// 	// BadCookie

// 	// EDE (Extended DNS Error) Codes
// 	// Other                      // 其他错误
// 	// UnsupportedDNSKEYAlgorithm // 不支持的DNSKEY算法
// 	// UnsupportedDSDigestType    // 不支持的DS摘要类型
// 	// StaleAnswer                // 过时的答案
// 	// ForgedAnswer               // 伪造的答案
// 	// DNSSECIndeterminate        // DNSSEC不确定
// 	// DNSSECBogus                // DNSSEC伪造
// 	// SecurityLame               // 安全瘸腿
// 	// BogusReferral              // 伪造的推荐
// 	// SignatureExpired           // 签名已过期
// 	// SignatureNotYetValid       // 签名尚未生效
// 	// KeyNotInZone               // 密钥不在区域中
// 	// InvalidSignature           // 无效的签名
// 	// AlgorithmNotSupported      // 不支持的算法
// 	// InvalidKey                 // 无效的密钥
// 	// InvalidAlgorithm           // 无效的算法
// 	// InvalidDS                  // 无效的DS
// 	// InvalidResponse            // 无效的响应
// 	// BadCookie_EDE              // 错误的Cookie
// 	// StaleNSEC                  // 过时的NSEC
// 	// StaleNXDOMAIN              // 过时的NXDOMAIN
// 	// DelegationRateLimited      // 委派率受限
// 	// HasEDE // 节点返回 EDE 的值
// )

const (
	Begin          NodeType = iota // 0
	FormErr                        // 1
	Serverfailure                  // 2
	NXDOMAIN                       // 3
	NotImplemented                 // 4
	Refused                        // 5
	Timeout                        // 6
	NoNsrecord                     // 7
	NsNotGlueIP                    // 8
	IPerror                        // 9
	IDMisMatch                     // 10
	LeaveA                         // 11
	LeaveAAAA                      // 12
	LeaveCNAME                     // 13
	SOA                            // 14
	Hijack                         // 15
	Common                         // 16
	NsInAnswer                     // 17
	PacketErr                      // 18
	YXDomain                       // 19
	Root                           // 20
	NonRoutableIP                  // 21
	YXRRSet
	NXRRSet
	NotAuthorized
	NotInZone
)

// Node 表示DNS解析依赖图中的一个节点
// type Node struct {
// 	Domain   string   // 域名
// 	IP       string   // IP地址
// 	QType    uint16   // 查询类型（例如：A，NS，CNAME）
// 	NodeID   int      // 节点的唯一标识符
// 	NodeType NodeType // 节点的类型
// }

// Node 表示DNS解析依赖图中的一个节点
type Node struct {
	Domain     string   // 域名
	IP         string   // IP地址
	QType      uint16   // 查询类型（例如：A，NS，CNAME）
	NameServer string   // Nameserver 的名字
	Zone       string   // zone
	NodeID     int      // 节点的唯一标识符Nodes
	NodeType   NodeType // 节点的类型
	Level      int      // 层次信息
	Isvisit    bool     // 标记节点是否访问过
}

// Edge 表示图中两个节点之间的有向边
type Edge struct {
	FromNodeID int    // 起始节点的ID
	ToNodeID   int    // 终止节点的ID
	Label      string // 描述关系的标签（可选）
}

// DNSGraph 表示DNS解析依赖图
type DNSGraph struct {
	Nodes   map[string]Node // 图中的节点映射,由<<domain,ip,qtype>> ->NodeID
	NodesID map[int]Node    // 图中的节点映射,由NodeID-> <<domain,ip,qtype>>
	Edges   map[string]Edge // 图中的边映射
	//mu     sync.Mutex      // 互斥锁，用于处理并发访问
	nextID int // 下一个将被分配的节点ID
	Domain string
}

var nodeTypeStrings = []string{
	"Begin",
	"FormErr",
	"Serverfailure",
	"NXDOMAIN",
	"NotImplemented",
	"Refused",
	"Timeout",
	"NoNsrecord",
	"NsNotGlueIP",
	"IPerror",
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

// var nodeTypeStrings = []string{
// 	"Begin",
// 	"FormErr",        // Rcode 1: 格式错误
// 	"Serverfailure",  // Rcode 2: 服务器失败
// 	"NXDOMAIN",       // Rcode 3: 名称错误
// 	"NotImplemented", // Rcode 4: 未实现
// 	"Refused",        // Rcode 5: 拒绝
// 	"YXDomain",       // Rcode 6: 域存在
// 	"YXRRSet",        // Rcode 7: RR集存在
// 	"NXRRSet",        // Rcode 8: RR集不存在
// 	"NotAuthorized",  // Rcode 9: 非授权
// 	"NotInZone",      // Rcode 10: 非区域
// 	"BadVersOrSig",   // Rcode 16: 错误版本或签名
// 	"BadKey",         // Rcode 17: 错误密钥
// 	"BadTime",        // Rcode 18: 时间错误
// 	"BadMode",        // Rcode 19: 模式错误
// 	"BadName",        // Rcode 20: 名称错误
// 	"BadAlg",         // Rcode 21: 算法错误
// 	"BadTrunc",       // Rcode 22: 截断错误
// 	"BadCookie",      // Rcode 23: Cookie错误
// 	"Timeout",
// 	"NoNsrecord",
// 	"NsNotGlueIP",
// 	"IPerror",
// 	"IDMisMatch",
// 	"LeaveA",
// 	"LeaveAAAA",
// 	"LeaveCNAME",
// 	"SOA",
// 	"Hijack",
// 	"Common",
// 	"NsInAnswer",
// 	"PacketErr",
// 	"Root",
// 	"NonRoutableIP",
// 	// EDE (Extended DNS Error) Codes
// 	"Other",                      // 其他错误
// 	"UnsupportedDNSKEYAlgorithm", // 不支持的DNSKEY算法
// 	"UnsupportedDSDigestType",    // 不支持的DS摘要类型
// 	"StaleAnswer",                // 过时的答案
// 	"ForgedAnswer",               // 伪造的答案
// 	"DNSSECIndeterminate",        // DNSSEC不确定
// 	"DNSSECBogus",                // DNSSEC伪造
// 	"SecurityLame",               // 安全瘸腿
// 	"BogusReferral",              // 伪造的推荐
// 	"SignatureExpired",           // 签名已过期
// 	"SignatureNotYetValid",       // 签名尚未生效
// 	"KeyNotInZone",               // 密钥不在区域中
// 	"InvalidSignature",           // 无效的签名
// 	"AlgorithmNotSupported",      // 不支持的算法
// 	"InvalidKey",                 // 无效的密钥
// 	"InvalidAlgorithm",           // 无效的算法
// 	"InvalidDS",                  // 无效的DS
// 	"InvalidResponse",            // 无效的响应
// 	"BadCookie_EDE",              // 错误的Cookie
// 	"StaleNSEC",                  // 过时的NSEC
// 	"StaleNXDOMAIN",              // 过时的NXDOMAIN
// 	"DelegationRateLimited",      // 委派率受限
// }

// nodeKey 生成用于节点映射的键
func nodeKey(domain, ip string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%s", domain, ip, qtype)
}

// SetNodeNameServer 为特定节点赋值 NameServer
func (graph *DNSGraph) SetNodeNameServer(domain string, ip string, qtype uint16, nameServer string) error {

	key := nodeKey(domain, ip, qtype)

	// 检查节点是否存在
	node, exists := graph.Nodes[key]
	if !exists {
		fmt.Printf("Node with key %s does not exist\n", key)
		return fmt.Errorf("Node with key %s does not exist", key)
	}

	// 为节点赋值 NameServer
	node.NameServer = nameServer

	// 更新图中的节点信息
	graph.Nodes[key] = node

	//fmt.Printf("Node with key %s and ID %d updated with NameServer: %s\n", key, node.NodeID, nameServer)
	return nil
}

// SetNodeNameServer 为特定节点赋值 NameServer
func (graph *DNSGraph) SetNodeZone(domain string, ip string, qtype uint16, zone string) error {

	key := nodeKey(domain, ip, qtype)

	// 检查节点是否存在
	node, exists := graph.Nodes[key]
	if !exists {
		fmt.Printf("--------------------Node with key %s does not exist\n", key)
		return fmt.Errorf("Node with key %s does not exist", key)
	}

	// 为节点赋值 Zone
	node.Zone = zone

	// 更新图中的节点信息
	graph.Nodes[key] = node

	//fmt.Println(node)

	//fmt.Printf("Node with key %s and ID %d updated with NameServer: %s\n", key, node.NodeID, nameServer)
	return nil
}

// Implement the json.Marshaler interface for NodeType
func (nt NodeType) MarshalJSON() ([]byte, error) {
	if int(nt) < 0 || int(nt) >= len(nodeTypeStrings) {
		return nil, fmt.Errorf("invalid NodeType: %d", nt)
	}
	return json.Marshal(nodeTypeStrings[nt])
}

// NewGraph 初始化并返回一个新的图
func NewGraph(domain string) *DNSGraph {
	return &DNSGraph{
		Nodes:  make(map[string]Node),
		Edges:  make(map[string]Edge),
		nextID: 1,
		Domain: domain,
	}
}

// IsNodeVisited 判断指定的节点是否已访问
func (g *DNSGraph) IsNodeVisited(domain, ip string, qtype uint16) bool {
	key := nodeKey(domain, ip, qtype)
	if node, exists := g.Nodes[key]; exists {
		return node.Isvisit
	}
	// fmt.Printf("Node with Domain: %s, IP: %s, QType: %d not found\n", domain, ip, qtype)
	return false
}

// MarkNodeVisited 标记指定的节点为已访问
func (g *DNSGraph) MarkNodeVisited(domain, ip string, qtype uint16) {
	key := nodeKey(domain, ip, qtype)
	if node, exists := g.Nodes[key]; exists {
		node.Isvisit = true
		g.Nodes[key] = node // 更新节点信息
	} else {
		// fmt.Printf("Node with Domain: %s, IP: %s, QType: %d not found\n", domain, ip, qtype)
	}
}

// AddNode 向图中添加一个新节点，并返回该节点的ID
// func (g *Graph) AddNode(domain, ip string, qtype uint16, nodeType NodeType) int {
// 	// g.mu.Lock()
// 	// defer g.mu.Unlock()

// 	key := nodeKey(domain, ip, qtype)
// 	if node, exists := g.Nodes[key]; exists {
// 		return node.NodeID
// 	}

// 	node := Node{
// 		Domain:   domain,
// 		IP:       ip,
// 		QType:    qtype,
// 		NodeID:   g.nextID,
// 		NodeType: nodeType,
// 	}
// 	g.Nodes[key] = node
// 	g.nextID++
// 	return node.NodeID
// }

// AddNode 添加节点到图中
func (g *DNSGraph) AddNode(domain, ip string, qType uint16, nodeType NodeType) int {

	key := nodeKey(domain, ip, qType)
	if node, exists := g.Nodes[key]; exists {
		g.SetNodeType(node.NodeID, nodeType)
		return node.NodeID
	}

	nodeID := g.nextID
	g.nextID++
	g.Nodes[key] = Node{
		Domain:     domain,
		IP:         ip,
		QType:      qType,
		NodeID:     nodeID,
		NodeType:   nodeType,
		NameServer: "",
		Zone:       "",
		Level:      -1, // 初始化层次信息为 -1
		Isvisit:    false,
	}
	return nodeID
}

// SetNodeLevel 设置指定节点的层次
func (g *DNSGraph) SetNodeLevel(domain, ip string, qtype uint16, level int) {
	key := nodeKey(domain, ip, qtype)
	if node, exists := g.Nodes[key]; exists {
		node.Level = level
		g.Nodes[key] = node // 更新节点信息
	} else {
		// fmt.Printf("Node with Domain: %s, IP: %s, QType: %d not found\n", domain, ip, qtype)
	}
}

// GetNodeID 根据域名、IP和查询类型返回节点ID
func (g *DNSGraph) GetNodeID(domain, ip string, qtype uint16) (int, bool) {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	if exists {
		return node.NodeID, true
	} else {
		NodeID := g.AddNode(domain, ip, qtype, 0)
		return NodeID, false
	}
}

// SetNodeType 设置指定节点ID的节点类型
func (g *DNSGraph) SetNodeType(nodeID int, nodeType NodeType) bool {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	for key, node := range g.Nodes {
		if node.NodeID == nodeID {
			node.NodeType = nodeType
			g.Nodes[key] = node
			return true
		}
	}
	return false
}

// AssignLevels 根据依赖关系分配层次信息
func (g *DNSGraph) AssignLevels() {
	visited := make(map[int]bool)
	var assign func(nodeID, level int)
	assign = func(nodeID, level int) {
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		for key, node := range g.Nodes {
			if node.NodeID == nodeID {
				g.Nodes[key] = Node{
					Domain:     node.Domain,
					IP:         node.IP,
					QType:      node.QType,
					NodeID:     node.NodeID,
					NameServer: node.NameServer,
					Zone:       node.Zone,
					NodeType:   node.NodeType,
					Level:      level,
					Isvisit:    node.Isvisit,
				}
				break
			}
		}

		for _, edge := range g.Edges {
			if edge.FromNodeID == nodeID {
				assign(edge.ToNodeID, level+1)
			}
		}
	}

	// 找到起始节点并开始分配层次信息
	for _, node := range g.Nodes {
		if node.IP == "begin" && node.Level == 0 {
			assign(node.NodeID, 0)
			break
		}
	}
}

func (g *DNSGraph) AddEdge(fromNodeID, toNodeID int, label string) {
	edgeKey := fmt.Sprintf("%d-%d", fromNodeID, toNodeID)
	if _, exists := g.Edges[edgeKey]; !exists {
		g.Edges[edgeKey] = Edge{
			FromNodeID: fromNodeID,
			ToNodeID:   toNodeID,
			Label:      label,
		}
	}
}

// GetNode 根据域名、IP和查询类型返回节点
func (g *DNSGraph) GetNode(domain, ip string, qtype uint16) (Node, bool) {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	key := nodeKey(domain, ip, qtype)
	node, exists := g.Nodes[key]
	return node, exists
}

// DNSGraphCollection 表示DNS解析图的集合
type DNSGraphCollection struct {
	Graphs map[string]*DNSGraph // 域名到图的映射
	mu     sync.Mutex           // 互斥锁，用于处理并发访问
}

// NewDNSGraphCollection 初始化并返回一个新的DNSGraphCollection
func NewDNSGraphCollection() *DNSGraphCollection {
	return &DNSGraphCollection{
		Graphs: make(map[string]*DNSGraph),
	}
}

// AddGraph 为特定域名添加一个新的图
// func (d *DNSGraphCollection) AddGraph(domain string) {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()

// 	if _, exists := d.Graphs[domain]; !exists {
// 		d.Graphs[domain] = NewGraph()
// 	}
// }

// GetGraph 返回特定域名的图
func (d *DNSGraphCollection) GetGraph(domain string) (*DNSGraph, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	graph, exists := d.Graphs[domain]
	return graph, exists
}

// AddNodeToGraph 向特定域名的图中添加一个节点
// func (d *DNSGraphCollection) AddNodeToGraph(domain, ip string, qtype uint16, nodeType NodeType) int {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()

// 	graph, exists := d.Graphs[domain]
// 	if !exists {
// 		graph = NewGraph()
// 		d.Graphs[domain] = graph
// 	}
// 	return graph.AddNode(domain, ip, qtype, nodeType)
// }

// // AddEdgeToGraph 向特定域名的图中添加一条边
// func (d *DNSGraphCollection) AddEdgeToGraph(domain string, fromNodeID, toNodeID int, label string) {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()

// 	graph, exists := d.Graphs[domain]
// 	if !exists {
// 		graph = NewGraph()
// 		d.Graphs[domain] = graph
// 	}
// 	graph.AddEdge(fromNodeID, toNodeID, label)
// }





// HasSelfLoop 检查图中是否存在一元环（节点自己指向自己）
func (g *DNSGraph) HasSelfLoop() bool {
    for _, edge := range g.Edges {
        if edge.FromNodeID == edge.ToNodeID {
            return true
        }
    }
    return false
}

// HasMultiNodeCycle 检查图中是否存在多元环（两个以上节点互相指向）
func (g *DNSGraph) HasMultiNodeCycle() bool {
    visited := make(map[int]bool)
    recStack := make(map[int]bool)

    for nodeID := range g.NodesID {
        if !visited[nodeID] {
            if g.hasCycleDFS(nodeID, visited, recStack) {
                return true
            }
        }
    }
    return false
}

// 辅助函数：使用DFS检测循环
func (g *DNSGraph) hasCycleDFS(nodeID int, visited, recStack map[int]bool) bool {
    visited[nodeID] = true
    recStack[nodeID] = true

    for _, edge := range g.Edges {
        if edge.FromNodeID == nodeID {
            if !visited[edge.ToNodeID] {
                if g.hasCycleDFS(edge.ToNodeID, visited, recStack) {
                    return true
                }
            } else if recStack[edge.ToNodeID] {
                return true
            }
        }
    }

    recStack[nodeID] = false
    return false
}


// GetCycleStats 返回一元环的个数、多元环的个数、最大环的节点数量以及最小环的节点数量
func (g *DNSGraph) GetCycleStats() (int, int, int, int) {
	// 遍历每个节点，查找所有环
	cycles:=g.FindAllCycles() 

	// 统计环的类型和最大、最小环的节点数量
	oneNodeCycleCount := 0
	multiNodeCycleCount := 0
	maxCycleSize := 0
	minCycleSize := -1

	for _, cycle := range cycles {
		if len(cycle) == 1 {
			oneNodeCycleCount++
		} else {
			multiNodeCycleCount++
			if len(cycle) > maxCycleSize {
				maxCycleSize = len(cycle)
			}
			if minCycleSize == -1 || len(cycle) < minCycleSize {
				minCycleSize = len(cycle)
			}
		}
	}

	// 返回统计结果
	return oneNodeCycleCount, multiNodeCycleCount, maxCycleSize, minCycleSize
}

// // HasCycleDFS 使用深度优先搜索检测环
// func (g *DNSGraph) HasSingleCycleDFS(nodeID int, visited map[int]bool, recStack map[int]bool, parent int) bool {
// 	if recStack[nodeID] {
// 		// 检测到环
// 		if parent == nodeID {
// 			// 一元环
// 			return true
// 		}
// 	}
// 	if visited[nodeID] {
// 		return false
// 	}

// 	visited[nodeID] = true
// 	recStack[nodeID] = true

// 	for _, edge := range g.Edges {
// 		if edge.FromNodeID == nodeID {
// 			hasUnaryCycle := g.HasSingleCycleDFS(edge.ToNodeID, visited, recStack, nodeID)
// 			if hasUnaryCycle {
// 				return hasUnaryCycle
// 			}
// 		}
// 	}

// 	recStack[nodeID] = false
// 	return false
// }

// func (g *DNSGraph) HasMultiCycleDFS(nodeID int, visited map[int]bool, recStack map[int]bool, parent int) bool {
// 	if recStack[nodeID] {
// 		// 检测到环
// 		if parent != nodeID {
// 			// 多元环
// 			return true
// 		}
// 	}
// 	if visited[nodeID] {
// 		return false
// 	}

// 	visited[nodeID] = true
// 	recStack[nodeID] = true

// 	for _, edge := range g.Edges {
// 		if edge.FromNodeID == nodeID {
// 			hasUnaryCycle := g.HasSingleCycleDFS(edge.ToNodeID, visited, recStack, nodeID)
// 			if hasUnaryCycle {
// 				return hasUnaryCycle
// 			}
// 		}
// 	}

// 	recStack[nodeID] = false
// 	return false
// }

// // DetectCycles 检测图中的环
// func (g *DNSGraph) DetectCycles() (bool, bool) {
// 	visited := make(map[int]bool)
// 	recStack := make(map[int]bool)
// 	hasUnaryCycle := false
// 	hasMultipleCycle := false

// 	for _, node := range g.Nodes {
// 		if !visited[node.NodeID] {
// 			unary := g.HasSingleCycleDFS(node.NodeID, visited, recStack, -1)
// 			multi := g.HasMultiCycleDFS(node.NodeID, visited, recStack, -1)
// 			if unary {
// 				hasUnaryCycle = true
// 			}
// 			if multi {
// 				hasMultipleCycle = true
// 			}
// 		}
// 	}

// 	return hasUnaryCycle, hasMultipleCycle
// }

// // HasCycleDFS 使用深度优先搜索检测环
// func (g *DNSGraph) HasCycleDFS(nodeID int, visited map[int]bool, recStack map[int]bool) bool {
// 	if recStack[nodeID] {
// 		return true
// 	}
// 	if visited[nodeID] {
// 		return false
// 	}

// 	visited[nodeID] = true
// 	recStack[nodeID] = true

// 	for _, edge := range g.Edges {
// 		if edge.FromNodeID == nodeID {
// 			if g.HasCycleDFS(edge.ToNodeID, visited, recStack) {
// 				return true
// 			}
// 		}
// 	}

// 	recStack[nodeID] = false
// 	return false
// }

// // HasCycle 检查图中是否存在环
// func (g *DNSGraph) HasCycle() bool {
// 	visited := make(map[int]bool)
// 	recStack := make(map[int]bool)

// 	for _, node := range g.Nodes {
// 		if g.HasCycleDFS(node.NodeID, visited, recStack) {
// 			return true
// 		}
// 	}
// 	return false
// }

// // FindAllCyclesDFS 查找所有环
// func (g *DNSGraph) FindAllCyclesDFS(nodeID int, visited map[int]bool, recStack []int, cycles *[][]int) {
// 	visited[nodeID] = true
// 	recStack = append(recStack, nodeID)

// 	for _, edge := range g.Edges {
// 		if edge.FromNodeID == nodeID {
// 			if contains(recStack, edge.ToNodeID) {
// 				cycle := append([]int(nil), recStack...)
// 				*cycles = append(*cycles, cycle)
// 			} else if !visited[edge.ToNodeID] {
// 				g.FindAllCyclesDFS(edge.ToNodeID, visited, recStack, cycles)
// 			}
// 		}
// 	}

// 	recStack = recStack[:len(recStack)-1]
// }


// FindAllCyclesDFS 查找所有环并打印它们
func (g *DNSGraph) FindAllCyclesDFS(nodeID int, visited map[int]bool, recStack []int, cycles *[][]int) {
	visited[nodeID] = true
	recStack = append(recStack, nodeID)

	for _, edge := range g.Edges {
		if edge.FromNodeID == nodeID {
			if contains(recStack, edge.ToNodeID) {
				// 找到环，记录完整环路
				cycle := make([]int, 0)
				startIndex := -1
				for i, id := range recStack {
					if id == edge.ToNodeID {
						startIndex = i
						break
					}
				}
				// 如果找到了环起点，记录完整的环
				if startIndex != -1 {
					cycle = append(cycle, recStack[startIndex:]...)
					*cycles = append(*cycles, cycle)
				}
			} else if !visited[edge.ToNodeID] {
				g.FindAllCyclesDFS(edge.ToNodeID, visited, recStack, cycles)
			}
		}
	}

	recStack = recStack[:len(recStack)-1]
}

// FindAllCycles 查找图中的所有环
func (g *DNSGraph) FindAllCycles() [][]int {
	visited := make(map[int]bool)
	var cycles [][]int

	for _, node := range g.Nodes {
		var recStack []int
		if !visited[node.NodeID] {
			g.FindAllCyclesDFS(node.NodeID, visited, recStack, &cycles)
		}
	}
	return cycles
}

// contains 检查切片中是否包含某个元素
func contains(slice []int, elem int) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

// PrintNodes 打印图中的所有节点
func (g *DNSGraph) PrintNodes() {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	for _, node := range g.Nodes {
		fmt.Printf("NodeID: %d, Domain: %s, IP: %s, QType: %s, NodeType: %d\n",
			node.NodeID, node.Domain, node.IP, QTypeToString(node.QType), node.NodeType)
	}
}

// PrintEdges 打印图中的所有边
func (g *DNSGraph) PrintEdges() {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	for _, edge := range g.Edges {
		fmt.Printf("%d > %d\n", edge.FromNodeID, edge.ToNodeID)
	}
}

func (g *DNSGraph) PrintGraph() {
	// 打印边
	fmt.Print(g.Domain,":[")
	for _, edge := range g.Edges {
		fmt.Printf("%d>%d,", edge.FromNodeID, edge.ToNodeID)
	}
	fmt.Print("]  ")

	// 打印点
	fmt.Print("[")
	for _, node := range g.Nodes {
		fmt.Printf("%d(%s, %s, %d) ", node.NodeID, node.IP, node.Domain, node.NodeType)
	}
	fmt.Println("]")
}


// // PrintGraph 打印图中的所有边，格式为 {节点1 (NodeType) -> 节点2 (NodeType), ...}
// func (g *DNSGraph) PrintGraph() {
// 	// g.mu.Lock()
// 	// defer g.mu.Unlock()

// 	fmt.Print("{")
// 	edgeCount := len(g.Edges)
// 	i := 0

// 	for _, edge := range g.Edges {
// 		fromNode, fromExists := g.NodesID[edge.FromNodeID]
// 		toNode, toExists := g.NodesID[edge.ToNodeID]

// 		// 确保起始和终止节点都存在于图中
// 		if fromExists && toExists {
// 			fmt.Printf("%s (%d) -> %s (%d)",
// 				fromNode.Domain, fromNode.NodeType,
// 				toNode.Domain, toNode.NodeType)
			
// 			// 如果不是最后一条边，添加逗号和空格
// 			if i < edgeCount-1 {
// 				fmt.Print(", ")
// 			}
// 		}
// 		i++
// 	}
// 	fmt.Println("}")
// }


// PrintCycles 打印图中的所有环
func (g *DNSGraph) PrintCycles() {
	cycles := g.FindAllCycles()
	for _, cycle := range cycles {
		fmt.Println(g.Domain,":", cycle)
	}
}

// PrintGraphDetails 打印图的详细信息，包括所有节点和所有边
func (g *DNSGraph) PrintGraphDetails() {
	// g.mu.Lock()
	// defer g.mu.Unlock()

	fmt.Printf("解析依赖拓扑图 (Domain: %s):\n", g.Domain)

	g.PrintNodes()
	g.PrintEdges()
}

// QTypeToString 将QType数值映射为对应的字符串表示
func QTypeToString(qType uint16) string {
	qTypeMap := map[uint16]string{
		1:  "A",
		2:  "NS",
		5:  "CNAME",
		6:  "SOA",
		12: "PTR",
		15: "MX",
		16: "TXT",
		28: "AAAA",
		// 添加其他需要的QType映射
	}

	if qTypeStr, found := qTypeMap[qType]; found {
		return qTypeStr
	}
	return fmt.Sprintf("Unknown(%d)", qType)
}

// func (g *Graph) ToJSON() string {
// 	data := struct {
// 		Nodes []Node `json:"nodes"`
// 		Edges []Edge `json:"edges"`
// 	}{
// 		Nodes: make([]Node, 0, len(g.Nodes)),
// 		Edges: g.Edges,
// 	}
// 	for _, node := range g.Nodes {
// 		data.Nodes = append(data.Nodes, node)
// 	}
// 	jsonData, err := json.Marshal(data)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(jsonData)
// }

func (g *DNSGraph) ToJSON() string {
	data := struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	}{
		Nodes: make([]Node, 0, len(g.Nodes)),
		Edges: make([]Edge, 0, len(g.Edges)),
	}
	for _, node := range g.Nodes {
		data.Nodes = append(data.Nodes, node)
	}
	for _, edge := range g.Edges {
		data.Edges = append(data.Edges, edge)
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")

	if err != nil {
		panic(err)
	}
	return string(jsonData)
}

// func (g *Graph) ToJSON() string {
// 	startNodeID := 1
// 	visited := make(map[int]bool)
// 	data := struct {
// 		Nodes []Node `json:"nodes"`
// 		Edges []Edge `json:"edges"`
// 	}{
// 		Nodes: make([]Node, 0),
// 		Edges: make([]Edge, 0),
// 	}

// 	// 深度优先遍历
// 	var dfs func(int)
// 	dfs = func(nodeID int) {
// 		node, ok := g.Nodes[fmt.Sprintf("%d", nodeID)]
// 		if !ok {
// 			return
// 		}

// 		visited[nodeID] = true
// 		data.Nodes = append(data.Nodes, node)

// 		for _, edge := range g.Edges {
// 			if edge.FromNodeID == nodeID && !visited[edge.ToNodeID] {
// 				data.Edges = append(data.Edges, edge)
// 				dfs(edge.ToNodeID)
// 			}
// 		}
// 	}

// 	dfs(startNodeID)

// 	jsonData, err := json.MarshalIndent(data, "", "  ")
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(jsonData)
// }

// // nodeAttributes 根据节点类型返回节点的颜色和形状
// func nodeAttributes(nodeType NodeType) (color string, shape string) {
// 	switch nodeType {
// 	case NoVisit:
// 		return "grey", "ellipse"
// 	case FormErr:
// 		return "red", "ellipse"
// 	case Serverfailure:
// 		return "orange", "ellipse"
// 	case NXDOMAIN, NXDOMAINNode:
// 		return "yellow", "ellipse"
// 	case NotImplemented, NotImplementedNode:
// 		return "purple", "ellipse"
// 	case Refused, RefusedNode:
// 		return "pink", "ellipse"
// 	case Timeout, TimeoutNode:
// 		return "blue", "ellipse"
// 	case NoNsrecord, NoNsrecordNode:
// 		return "green", "ellipse"
// 	case NsNotGlueIP, NsNotGlueIPNode:
// 		return "brown", "ellipse"
// 	case IPerror, IPerrorNode:
// 		return "black", "ellipse"
// 	case IDMisMatch, IDMisMatchNode:
// 		return "cyan", "ellipse"
// 	case LeaveA, LeaveANode:
// 		return "magenta", "ellipse"
// 	case LeaveAAAA, LeaveAAAANode:
// 		return "lime", "ellipse"
// 	case LeaveCNAME, LeaveCNAMENode:
// 		return "gold", "ellipse"
// 	case SOA, SOANode:
// 		return "silver", "ellipse"
// 	case Hijack, HijackNode:
// 		return "darkred", "ellipse"
// 	case Common:
// 		return "white", "ellipse"
// 	default:
// 		return "lightgrey", "ellipse"
// 	}
// }

// // DrawGraph 生成DOT文件并调用Graphviz生成PNG图片
// func (g *Graph) DrawGraph(filename string) error {
// 	// 创建一个新的有向图
// 	dotGraph := simple.NewDirectedGraph()

// 	// 创建一个节点ID到Graphviz节点的映射
// 	nodeMap := make(map[int]graph.Node)

// 	// 添加节点到Graphviz图
// 	for _, node := range g.Nodes {
// 		n := dotGraph.NewNode()
// 		n.SetID(int64(node.NodeID))
// 		nodeMap[node.NodeID] = n
// 		dotGraph.AddNode(n)

// 		// 设置节点的颜色和形状
// 		color, shape := nodeAttributes(node.NodeType)
// 		dotGraph.SetNodeAttribute(n, "color", color)
// 		dotGraph.SetNodeAttribute(n, "shape", shape)
// 	}

// 	// 添加边到Graphviz图
// 	for _, edge := range g.Edges {
// 		fromNode := nodeMap[edge.FromNodeID]
// 		toNode := nodeMap[edge.ToNodeID]
// 		e := dotGraph.NewEdge(fromNode, toNode)
// 		dotGraph.SetEdge(e)
// 	}

// 	// 生成DOT描述
// 	data, err := dot.Marshal(dotGraph, "DNSGraph", "", "  ")
// 	if err != nil {
// 		return err
// 	}

// 	// 将DOT描述写入文件
// 	dotFilename := filename + ".dot"
// 	err = os.WriteFile(dotFilename, data, 0644)
// 	if err != nil {
// 		return err
// 	}

// 	// 使用Graphviz将DOT文件转换为PNG图片
// 	cmd := exec.Command("dot", "-Tpng", dotFilename, "-o", filename)
// 	err = cmd.Run()
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// func main() {
// 	collection := NewDNSGraphCollection()

// 	// 添加多个图
// 	collection.AddGraph("example.com")
// 	collection.AddGraph("example.net")
// 	collection.AddGraph("example.org")

// 	// 添加多个节点和边到每个图中
// 	nodeID1 := collection.AddNodeToGraph("example.com", "93.184.216.34", "A", 1)
// 	nodeID2 := collection.AddNodeToGraph("example.com", "ns1.example.com", "NS", 2)
// 	nodeID3 := collection.AddNodeToGraph("ns1.example.com", "192.0.2.1", "A", 3)
// 	nodeID4 := collection.AddNodeToGraph("example.com", "93.184.216.34", "A", 4)
// 	nodeID5 := collection.AddNodeToGraph("example.net", "2001:db8:85a3:8d3:1319:8a2e:370:7348", "AAAA", 5)
// 	nodeID6 := collection.AddNodeToGraph("example.org", "mx1.example.org", "MX", 6)

// 	collection.AddEdgeToGraph("example.com", nodeID1, nodeID2, "NS lookup")
// 	collection.AddEdgeToGraph("example.com", nodeID2, nodeID3, "A lookup")
// 	collection.AddEdgeToGraph("example.com", nodeID3, nodeID4, "answer")
// 	collection.AddEdgeToGraph("example.net", nodeID5, nodeID6, "MX lookup")
// 	collection.AddEdgeToGraph("example.org", nodeID6, nodeID1, "returning mail")

// 	// 添加多个环到不同图中
// 	collection.AddEdgeToGraph("example.com", nodeID4, nodeID1, "cyclic edge")
// 	collection.AddEdgeToGraph("example.net", nodeID5, nodeID6, "cyclic edge")

// 	// 获取并打印每个图的节点、边和环
// 	graph1, found1 := collection.GetGraph("example.com")
// 	if found1 {
// 		fmt.Printf("Graph for domain 'example.com':\n")
// 		fmt.Println("All nodes:")
// 		graph1.PrintNodes()
// 		fmt.Println("All edges:")
// 		graph1.PrintEdges()
// 		fmt.Println("All cycles:")
// 		graph1.PrintCycles()
// 	} else {
// 		fmt.Println("Graph for domain 'example.com' not found")
// 	}

// 	graph2, found2 := collection.GetGraph("example.net")
// 	if found2 {
// 		fmt.Printf("Graph for domain 'example.net':\n")
// 		fmt.Println("All nodes:")
// 		graph2.PrintNodes()
// 		fmt.Println("All edges:")
// 		graph2.PrintEdges()
// 		fmt.Println("All cycles:")
// 		graph2.PrintCycles()
// 	} else {
// 		fmt.Println("Graph for domain 'example.net' not found")
// 	}

// 	graph3, found3 := collection.GetGraph("example.org")
// 	if found3 {
// 		fmt.Printf("Graph for domain 'example.org':\n")
// 		fmt.Println("All nodes:")
// 		graph3.PrintNodes()
// 		fmt.Println("All edges:")
// 		graph3.PrintEdges()
// 		fmt.Println("All cycles:")
// 		graph3.PrintCycles()
// 	} else {
// 		fmt.Println("Graph for domain 'example.org' not found")
// 	}
// }
