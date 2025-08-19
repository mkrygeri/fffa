// Unified Go loader for XDP + ring buffer collector with AWS Flow Log–style enrichment
// Load BPF from compiled object and attach to XDP

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	BPFObjFile      = "fffa.bpf.o"
	ProgramName     = "xdp_prog"
	RingMapName     = "flow_ring"
	IfaceName       = "ens5"
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

type FlowEvent struct {
	Key         FlowKey
	TimestampNs uint64
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

func fetchMetadata() {
	if time.Since(lastMetaFetch) < RefreshInterval {
		return
	}

	// Step 1: Get IMDSv2 token
	tokenReq, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	client := &http.Client{Timeout: 2 * time.Second}
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		log.Printf("metadata token error: %v", err)
		return
	}
	defer tokenResp.Body.Close()
	tokenBytes, err := ioutil.ReadAll(tokenResp.Body)
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
	mac, err := os.ReadFile("/sys/class/net/" + IfaceName + "/address")
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
			vpcID, _ := ioutil.ReadAll(resp2.Body)
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
			subnetID, _ := ioutil.ReadAll(resp3.Body)
			metadata.SubnetID = string(subnetID)
		}
	}
}

func main() {
	iface, err := net.InterfaceByName(IfaceName)
	if err != nil {
		log.Fatalf("interface lookup: %v", err)
	}
	fmt.Printf("Attaching to interface: %s (index %d)\n", IfaceName, iface.Index)

	spec, err := ebpf.LoadCollectionSpec(BPFObjFile)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[ProgramName]
	if prog == nil {
		log.Fatalf("program %q not found in %s", ProgramName, BPFObjFile)
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attach XDP: %v", err)
	}
	defer lnk.Close()

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

	flows := make(map[FlowKey]time.Time)
	agingInterval := 10 * time.Second
	idleTimeout := 60 * time.Second

	go func() {
		ticker := time.NewTicker(agingInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for k, last := range flows {
				if now.Sub(last) > idleTimeout {
					fmt.Printf("flow expired: %+v\n", k)
					delete(flows, k)
				}
			}
		}
	}()

	go func() {
		for {
			fetchMetadata()

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
			ts := time.Unix(0, int64(ev.TimestampNs)).Format(time.RFC3339)
			flows[key] = time.Now()
			fmt.Printf("flowlog version=2 proto=%s src=%s:%d dst=%s:%d pkt-src=%s pkt-dst=%s direction=%d encapsulated=%v account=%s vpc=%s subnet=%s instance=%s az=%s region=%s time=%s\n",
				protoStr(key.InnerProto),
				ipStr(key.OuterSrcIP), key.InnerSrcPort,
				ipStr(key.OuterDstIP), key.InnerDstPort,
				ipStr(key.InnerSrcIP), ipStr(key.InnerDstIP),
				key.Direction,
				key.IsEncapsulated != 0,
				metadata.AccountID,
				metadata.VpcID,
				metadata.SubnetID,
				metadata.InstanceID,
				metadata.AvailabilityZone,
				metadata.Region,
				ts,
			)
		}
	}()

	<-sigs
	fmt.Println("Detaching and exiting...")
}
