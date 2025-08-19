// Unified Go loader for XDP + ring buffer collector with AWS Flow Log–style enrichment
// Load BPF from compiled object and attach to XDP

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	BPFObjFile      = "bpf/flow_monitor.o"
	ProgramName     = "xdp_prog"
	RingMapName     = "flow_ring"
	DefaultIfaceName = "ens5"
	MetadataURL     = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	RefreshInterval = 300 * time.Second
)

type FlowKey struct {
	OuterSrcIP     uint32
	OuterDstIP     uint32
	InnerSrcIP     uint32
	InnerDstIP     uint32
	InnerSrcPort   uint16
	InnerDstPort   uint16
	InnerProto     uint8
	Direction      uint8
	IsEncapsulated uint8
}

// Netfilter verdict and rule information
type NetfilterInfo struct {
	Verdict    uint32   // NF_ACCEPT=1, NF_DROP=0, NF_STOLEN=2, NF_QUEUE=3, NF_REPEAT=4
	Hook       uint32   // NF_INET_PRE_ROUTING=0, NF_INET_LOCAL_IN=1, NF_INET_FORWARD=2, etc.
	Priority   int32    // Hook priority
	TableName  [16]int8 // iptables table name (filter, nat, mangle, raw)
	ChainName  [32]int8 // iptables chain name (INPUT, OUTPUT, FORWARD, etc.)
	RuleNum    uint32   // Rule number in chain
	RuleTarget [32]int8 // Target name (ACCEPT, DROP, REJECT, custom target)
	MatchInfo  [64]int8 // Match information (protocol, port, etc.)
}

// Enhanced flow statistics with network quality metrics
type FlowStats struct {
	Packets    uint64
	Bytes      uint64
	StartNs    uint64
	LastSeenNs uint64
	TCPFlags   uint8

	// Connection establishment metrics
	SynTimestamp      uint64
	SynAckTimestamp   uint64
	AckTimestamp      uint64
	HandshakeLatencyUs uint32

	// Retransmission tracking
	Retransmissions     uint32
	FastRetransmits     uint32
	TimeoutRetransmits  uint32
	LastSeq             uint32
	LastSeqTimestamp    uint64

	// Jitter and timing metrics
	PktIntervals  [5]uint64 // JITTER_WINDOW_SIZE = 5
	IntervalIndex uint8
	AvgJitterUs   uint32
	MaxJitterUs   uint32

	// Window and congestion metrics
	LastWindowSize uint16
	MinWindowSize  uint16
	MaxWindowSize  uint16
	ECNFlags       uint8

	// Quality metrics
	OutOfOrderPkts  uint32
	DuplicateAcks   uint32
	TotalRTTSamples uint64
	SumRTTUs        uint64
	MinRTTUs        uint32
	MaxRTTUs        uint32

	// Netfilter information (matching the eBPF struct)
	NetfilterInfo NetfilterInfo
	LastVerdict   uint32
}

type FlowEvent struct {
	Key         FlowKey
	TimestampNs uint64
	Metrics     FlowStats
}

// Enhanced flow cache entry that stores all metrics
type FlowCacheEntry struct {
	Key            FlowKey
	LastSeen       time.Time
	FirstSeen      time.Time
	Metrics        FlowStats
	MetricsUpdated bool // Flag to track if metrics were updated since last output
}

type InstanceMeta struct {
	AccountID        string `json:"accountId"`
	InstanceID       string `json:"instanceId"`
	Region           string `json:"region"`
	AvailabilityZone string `json:"availabilityZone"`
	PrivateIP        string `json:"privateIp"`
	SubnetID         string `json:"subnetId"`
	VpcID            string `json:"vpcId"`
}

var metadata InstanceMeta
var lastMetaFetch time.Time

func ipStr(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

func protoStr(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", p)
	}
}

// Calculate average RTT from samples
func calculateAvgRTT(stats *FlowStats) uint32 {
	if stats.TotalRTTSamples == 0 {
		return 0
	}
	return uint32(stats.SumRTTUs / stats.TotalRTTSamples)
}

// Format TCP flags as human-readable string
func formatTCPFlags(flags uint8) string {
	var flagStrs []string
	if flags&0x01 != 0 {
		flagStrs = append(flagStrs, "FIN")
	}
	if flags&0x02 != 0 {
		flagStrs = append(flagStrs, "SYN")
	}
	if flags&0x04 != 0 {
		flagStrs = append(flagStrs, "RST")
	}
	if flags&0x08 != 0 {
		flagStrs = append(flagStrs, "PSH")
	}
	if flags&0x10 != 0 {
		flagStrs = append(flagStrs, "ACK")
	}
	if flags&0x20 != 0 {
		flagStrs = append(flagStrs, "URG")
	}
	if flags&0x40 != 0 {
		flagStrs = append(flagStrs, "ECE")
	}
	if flags&0x80 != 0 {
		flagStrs = append(flagStrs, "CWR")
	}

	if len(flagStrs) == 0 {
		return "NONE"
	}
	return strings.Join(flagStrs, "|")
}

// Convert C string (int8 array) to Go string
func cStringToString(cstr []int8) string {
	buf := make([]byte, 0, len(cstr))
	for _, c := range cstr {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// Convert netfilter verdict code to string
func getVerdictString(verdict uint32) string {
	switch verdict {
	case 0:
		return "DROP"
	case 1:
		return "ACCEPT"
	case 2:
		return "STOLEN"
	case 3:
		return "QUEUE"
	case 4:
		return "REPEAT"
	case 5:
		return "STOP"
	default:
		return fmt.Sprintf("UNKNOWN_%d", verdict)
	}
}

// Convert netfilter hook to string
func getHookString(hook uint32) string {
	switch hook {
	case 0:
		return "NF_INET_PRE_ROUTING"
	case 1:
		return "NF_INET_LOCAL_IN"
	case 2:
		return "NF_INET_FORWARD"
	case 3:
		return "NF_INET_LOCAL_OUT"
	case 4:
		return "NF_INET_POST_ROUTING"
	default:
		return fmt.Sprintf("UNKNOWN_HOOK_%d", hook)
	}
}

// Format flow metrics as JSON with null values for non-applicable metrics
func formatFlowMetricsJSON(entry *FlowCacheEntry, metadata InstanceMeta, ts string) string {
	key := entry.Key
	metrics := entry.Metrics

	metricsMap := map[string]interface{}{
		"version":      "3", // Enhanced version
		"timestamp":    ts,
		"proto":        protoStr(key.InnerProto),
		"src_ip":       ipStr(key.OuterSrcIP),
		"src_port":     key.InnerSrcPort,
		"dst_ip":       ipStr(key.OuterDstIP),
		"dst_port":     key.InnerDstPort,
		"pkt_src_ip":   ipStr(key.InnerSrcIP),
		"pkt_dst_ip":   ipStr(key.InnerDstIP),
		"direction":    key.Direction,
		"encapsulated": key.IsEncapsulated != 0,
		"packets":      metrics.Packets,
		"bytes":        metrics.Bytes,
		"first_seen":   entry.FirstSeen.Format(time.RFC3339),
		"last_seen":    entry.LastSeen.Format(time.RFC3339),
		"duration_ms":  entry.LastSeen.Sub(entry.FirstSeen).Milliseconds(),
	}

	// Add TCP-specific metrics or null values
	if key.InnerProto == 6 { // TCP
		metricsMap["tcp_flags"] = formatTCPFlags(metrics.TCPFlags)

		// Connection establishment metrics (null if not measured)
		if metrics.HandshakeLatencyUs > 0 {
			metricsMap["handshake_latency_us"] = metrics.HandshakeLatencyUs
		} else {
			metricsMap["handshake_latency_us"] = nil
		}

		// Retransmission metrics
		metricsMap["retransmissions"] = metrics.Retransmissions
		metricsMap["fast_retransmits"] = metrics.FastRetransmits
		metricsMap["timeout_retransmits"] = metrics.TimeoutRetransmits

		// Jitter metrics (null if not calculated)
		if metrics.AvgJitterUs > 0 {
			metricsMap["avg_jitter_us"] = metrics.AvgJitterUs
			metricsMap["max_jitter_us"] = metrics.MaxJitterUs
		} else {
			metricsMap["avg_jitter_us"] = nil
			metricsMap["max_jitter_us"] = nil
		}

		// Window size metrics (null if not observed)
		if metrics.MaxWindowSize > 0 {
			metricsMap["min_window_size"] = metrics.MinWindowSize
			metricsMap["max_window_size"] = metrics.MaxWindowSize
			metricsMap["last_window_size"] = metrics.LastWindowSize
		} else {
			metricsMap["min_window_size"] = nil
			metricsMap["max_window_size"] = nil
			metricsMap["last_window_size"] = nil
		}

		// Quality metrics
		metricsMap["out_of_order_pkts"] = metrics.OutOfOrderPkts
		metricsMap["duplicate_acks"] = metrics.DuplicateAcks

		// RTT metrics (null if not measured)
		if metrics.TotalRTTSamples > 0 {
			metricsMap["min_rtt_us"] = metrics.MinRTTUs
			metricsMap["max_rtt_us"] = metrics.MaxRTTUs
			metricsMap["avg_rtt_us"] = calculateAvgRTT(&metrics)
			metricsMap["rtt_samples"] = metrics.TotalRTTSamples
		} else {
			metricsMap["min_rtt_us"] = nil
			metricsMap["max_rtt_us"] = nil
			metricsMap["avg_rtt_us"] = nil
			metricsMap["rtt_samples"] = 0
		}

		// ECN flags
		metricsMap["ecn_flags"] = metrics.ECNFlags

	} else {
		// For non-TCP protocols, set TCP-specific metrics to null
		metricsMap["tcp_flags"] = nil
		metricsMap["handshake_latency_us"] = nil
		metricsMap["retransmissions"] = nil
		metricsMap["fast_retransmits"] = nil
		metricsMap["timeout_retransmits"] = nil
		metricsMap["avg_jitter_us"] = nil
		metricsMap["max_jitter_us"] = nil
		metricsMap["min_window_size"] = nil
		metricsMap["max_window_size"] = nil
		metricsMap["last_window_size"] = nil
		metricsMap["out_of_order_pkts"] = nil
		metricsMap["duplicate_acks"] = nil
		metricsMap["min_rtt_us"] = nil
		metricsMap["max_rtt_us"] = nil
		metricsMap["avg_rtt_us"] = nil
		metricsMap["rtt_samples"] = nil
		metricsMap["ecn_flags"] = nil
	}

	// Netfilter verdict information (applies to all protocols since netfilter operates at IP level)
	if metrics.LastVerdict > 0 {
		metricsMap["netfilter_verdict"] = getVerdictString(metrics.LastVerdict)
		metricsMap["netfilter_hook"] = getHookString(metrics.NetfilterInfo.Hook)
		metricsMap["netfilter_priority"] = metrics.NetfilterInfo.Priority
		metricsMap["netfilter_table"] = cStringToString(metrics.NetfilterInfo.TableName[:])
		metricsMap["netfilter_chain"] = cStringToString(metrics.NetfilterInfo.ChainName[:])
		if metrics.NetfilterInfo.RuleNum > 0 {
			metricsMap["netfilter_rule_num"] = metrics.NetfilterInfo.RuleNum
		} else {
			metricsMap["netfilter_rule_num"] = nil
		}
		metricsMap["netfilter_target"] = cStringToString(metrics.NetfilterInfo.RuleTarget[:])
		metricsMap["netfilter_match_info"] = cStringToString(metrics.NetfilterInfo.MatchInfo[:])

		// Individual verdict counts (flattened instead of nested)
		metricsMap["netfilter_accepts"] = uint32(0)   // Simplified for now
		metricsMap["netfilter_drops"] = uint32(0)     // Simplified for now
		metricsMap["netfilter_rejects"] = uint32(0)   // Simplified for now
		metricsMap["netfilter_queues"] = uint32(0)    // Simplified for now
	} else {
		// No netfilter events captured for this flow (set to null)
		metricsMap["netfilter_verdict"] = nil
		metricsMap["netfilter_hook"] = nil
		metricsMap["netfilter_priority"] = nil
		metricsMap["netfilter_table"] = nil
		metricsMap["netfilter_chain"] = nil
		metricsMap["netfilter_rule_num"] = nil
		metricsMap["netfilter_target"] = nil
		metricsMap["netfilter_match_info"] = nil
		metricsMap["netfilter_accepts"] = nil
		metricsMap["netfilter_drops"] = nil
		metricsMap["netfilter_rejects"] = nil
		metricsMap["netfilter_queues"] = nil
	} // AWS metadata
	metricsMap["aws_account"] = metadata.AccountID
	metricsMap["aws_vpc"] = metadata.VpcID
	metricsMap["aws_subnet"] = metadata.SubnetID
	metricsMap["aws_instance"] = metadata.InstanceID
	metricsMap["aws_az"] = metadata.AvailabilityZone
	metricsMap["aws_region"] = metadata.Region

	jsonBytes, _ := json.Marshal(metricsMap)
	return string(jsonBytes)
}

func fetchMetadata(interfaceName string) {
	if time.Since(lastMetaFetch) < RefreshInterval {
		return
	}

	// Step 1: Get IMDSv2 token
	tokenReq, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		log.Printf("create token request error: %v", err)
		return
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	client := &http.Client{Timeout: 2 * time.Second}
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		log.Printf("metadata token error: %v", err)
		return
	}
	defer tokenResp.Body.Close()
	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		log.Printf("read token body: %v", err)
		return
	}
	token := string(tokenBytes)

	// Step 2: Use token to fetch metadata
	metaReq, err := http.NewRequest("GET", MetadataURL, nil)
	if err != nil {
		log.Printf("new metadata request error: %v", err)
		return
	}
	metaReq.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := client.Do(metaReq)
	if err != nil {
		log.Printf("metadata fetch error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &metadata); err != nil {
		log.Printf("unmarshal metadata: %v", err)
		return
	}
	lastMetaFetch = time.Now()

	// Step 3: Get VPC and Subnet ID from network interface metadata
	mac, err := os.ReadFile("/sys/class/net/" + interfaceName + "/address")
	if err != nil {
		log.Printf("get MAC address: %v", err)
		return
	}
	macAddr := strings.TrimSpace(string(mac)) + "/"

	eniURL := "http://169.254.169.254/latest/meta-data/network/interfaces/macs/" + macAddr

	// Fetch VPC ID
	vpcReq, err := http.NewRequest("GET", eniURL+"vpc-id", nil)
	if err == nil {
		vpcReq.Header.Set("X-aws-ec2-metadata-token", token)
		resp2, err := client.Do(vpcReq)
		if err == nil {
			defer resp2.Body.Close()
			vpcID, _ := io.ReadAll(resp2.Body)
			metadata.VpcID = string(vpcID)
		}
	}

	// Fetch Subnet ID
	subnetReq, err := http.NewRequest("GET", eniURL+"subnet-id", nil)
	if err == nil {
		subnetReq.Header.Set("X-aws-ec2-metadata-token", token)
		resp3, err := client.Do(subnetReq)
		if err == nil {
			defer resp3.Body.Close()
			subnetID, _ := io.ReadAll(resp3.Body)
			metadata.SubnetID = string(subnetID)
		}
	}
}

// Get all available network interfaces
func getAllInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	var names []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			names = append(names, iface.Name)
		}
	}
	return names, nil
}

// Attach XDP program to a single interface
func attachToInterface(coll *ebpf.Collection, ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup for %s: %v", ifaceName, err)
	}
	
	prog := coll.Programs[ProgramName]
	if prog == nil {
		return nil, fmt.Errorf("program %q not found", ProgramName)
	}
	
	fmt.Printf("Attaching to interface: %s (index %d)\n", ifaceName, iface.Index)
	
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("attach XDP to %s: %v", ifaceName, err)
	}
	
	return lnk, nil
}

// Show usage information
func showUsage() {
	fmt.Printf("FFFA - Flow Monitor with eBPF\n\n")
	fmt.Printf("Usage: %s [options]\n\n", os.Args[0])
	fmt.Printf("Options:\n")
	fmt.Printf("  -i, --interface <name>    Interface to monitor (default: %s)\n", DefaultIfaceName)
	fmt.Printf("  -a, --all-interfaces      Monitor all available interfaces\n")
	fmt.Printf("  -l, --list-interfaces     List available interfaces and exit\n")
	fmt.Printf("  -h, --help               Show this help message\n\n")
	fmt.Printf("Examples:\n")
	fmt.Printf("  %s -i eth0                Monitor eth0 interface\n", os.Args[0])
	fmt.Printf("  %s -a                     Monitor all interfaces\n", os.Args[0])
	fmt.Printf("  %s -l                     List available interfaces\n", os.Args[0])
}

func main() {
	// Parse command line arguments
	var ifaceName = flag.String("i", DefaultIfaceName, "Interface to monitor")
	var interfaceFlag = flag.String("interface", DefaultIfaceName, "Interface to monitor")
	var allInterfaces = flag.Bool("a", false, "Monitor all available interfaces")
	var allInterfacesFlag = flag.Bool("all-interfaces", false, "Monitor all available interfaces")
	var listInterfaces = flag.Bool("l", false, "List available interfaces and exit")
	var listInterfacesFlag = flag.Bool("list-interfaces", false, "List available interfaces and exit")
	var showHelp = flag.Bool("h", false, "Show help message")
	var showHelpFlag = flag.Bool("help", false, "Show help message")
	
	flag.Parse()
	
	// Handle help
	if *showHelp || *showHelpFlag {
		showUsage()
		return
	}
	
	// Handle list interfaces
	if *listInterfaces || *listInterfacesFlag {
		interfaces, err := getAllInterfaces()
		if err != nil {
			log.Fatalf("Failed to get interfaces: %v", err)
		}
		fmt.Printf("Available interfaces:\n")
		for _, name := range interfaces {
			fmt.Printf("  %s\n", name)
		}
		return
	}
	
	// Determine which interface(s) to use
	var targetInterfaces []string
	if *allInterfaces || *allInterfacesFlag {
		interfaces, err := getAllInterfaces()
		if err != nil {
			log.Fatalf("Failed to get interfaces: %v", err)
		}
		if len(interfaces) == 0 {
			log.Fatalf("No suitable interfaces found")
		}
		targetInterfaces = interfaces
		fmt.Printf("Monitoring all interfaces: %s\n", strings.Join(interfaces, ", "))
	} else {
		// Use -i flag value, or --interface flag value, with -i taking precedence
		selectedInterface := *ifaceName
		if *interfaceFlag != DefaultIfaceName {
			selectedInterface = *interfaceFlag
		}
		targetInterfaces = []string{selectedInterface}
	}

	spec, err := ebpf.LoadCollectionSpec(BPFObjFile)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	// Attach to all target interfaces
	var links []link.Link
	for _, targetInterface := range targetInterfaces {
		lnk, err := attachToInterface(coll, targetInterface)
		if err != nil {
			// Clean up any successfully attached links
			for _, prevLink := range links {
				prevLink.Close()
			}
			log.Fatalf("Failed to attach to interface %s: %v", targetInterface, err)
		}
		links = append(links, lnk)
	}

	fmt.Printf("Successfully attached to %d interface(s)\n", len(links))

	// Clean up links when done
	defer func() {
		for i, lnk := range links {
			fmt.Printf("Detaching from interface %s\n", targetInterfaces[i])
			lnk.Close()
		}
	}()

	ring, ok := coll.Maps[RingMapName]
	if !ok {
		log.Fatalf("ring map %q not found", RingMapName)
	}

	sub, err := ringbuf.NewReader(ring)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer sub.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Started flow tracker. Press Ctrl+C to exit.")

	// Enhanced flow cache with comprehensive metrics
	flowCache := make(map[FlowKey]*FlowCacheEntry)
	agingInterval := 10 * time.Second
	idleTimeout := 60 * time.Second
	outputInterval := 5 * time.Second // Output cached flows every 5 seconds

	// Flow aging goroutine
	go func() {
		ticker := time.NewTicker(agingInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for k, entry := range flowCache {
				if now.Sub(entry.LastSeen) > idleTimeout {
					// Output final metrics before expiring
					fmt.Printf("flowlog %s\n", formatFlowMetricsJSON(entry, metadata, now.Format(time.RFC3339)))
					delete(flowCache, k)
				}
			}
		}
	}()

	// Periodic output of cached flows
	go func() {
		ticker := time.NewTicker(outputInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for _, entry := range flowCache {
				if entry.MetricsUpdated {
					fmt.Printf("flowlog %s\n", formatFlowMetricsJSON(entry, metadata, now.Format(time.RFC3339)))
					entry.MetricsUpdated = false // Reset flag after output
				}
			}
		}
	}()

	// Main event processing goroutine
	go func() {
		for {
			fetchMetadata(targetInterfaces[0])

			record, err := sub.Read()
			if err != nil {
				log.Printf("ring read: %v", err)
				continue
			}

			var ev FlowEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("decode error: %v", err)
				continue
			}

			key := ev.Key
			metrics := ev.Metrics
			now := time.Now()

			// Update or create flow cache entry
			entry, exists := flowCache[key]
			if !exists {
				// Create new cache entry
				entry = &FlowCacheEntry{
					Key:       key,
					FirstSeen: now,
					LastSeen:       now,
					Metrics:        metrics,
					MetricsUpdated: true,
				}
				flowCache[key] = entry
			} else {
				// Update existing entry
				entry.LastSeen = now
				entry.Metrics = metrics
				entry.MetricsUpdated = true
			}
		}
	}()

	<-sigs
	fmt.Println("Detaching and exiting...")
}
