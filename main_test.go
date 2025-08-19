package main

import (
	"testing"
)

func TestIPStr(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{
			name:     "localhost",
			input:    0x0100007f, // 127.0.0.1 in little-endian
			expected: "127.0.0.1",
		},
		{
			name:     "zero IP",
			input:    0,
			expected: "0.0.0.0",
		},
		{
			name:     "private IP",
			input:    0x0164a8c0, // 192.168.100.1 in little-endian
			expected: "192.168.100.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipStr(tt.input)
			if result != tt.expected {
				t.Errorf("ipStr(%d) = %s; expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestProtoStr(t *testing.T) {
	tests := []struct {
		name     string
		input    uint8
		expected string
	}{
		{
			name:     "TCP",
			input:    6,
			expected: "TCP",
		},
		{
			name:     "UDP",
			input:    17,
			expected: "UDP",
		},
		{
			name:     "unknown protocol",
			input:    255,
			expected: "PROTO_255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protoStr(tt.input)
			if result != tt.expected {
				t.Errorf("protoStr(%d) = %s; expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFlowKeyStructure(t *testing.T) {
	// Test that FlowKey struct can be created and accessed
	key := FlowKey{
		OuterSrcIP:     0x0100007f,
		OuterDstIP:     0x0200007f,
		InnerSrcIP:     0x0300007f,
		InnerDstIP:     0x0400007f,
		InnerSrcPort:   8080,
		InnerDstPort:   443,
		InnerProto:     6,
		Direction:      0,
		IsEncapsulated: 1,
	}

	if key.InnerProto != 6 {
		t.Errorf("Expected protocol 6, got %d", key.InnerProto)
	}
	if key.InnerSrcPort != 8080 {
		t.Errorf("Expected source port 8080, got %d", key.InnerSrcPort)
	}
}

func TestInstanceMetaStructure(t *testing.T) {
	// Test that InstanceMeta struct can be created
	meta := InstanceMeta{
		AccountID:        "123456789012",
		InstanceID:       "i-1234567890abcdef0",
		Region:           "us-east-1",
		AvailabilityZone: "us-east-1a",
		PrivateIP:        "10.0.1.100",
		SubnetID:         "subnet-12345678",
		VpcID:            "vpc-87654321",
	}

	if meta.Region != "us-east-1" {
		t.Errorf("Expected region us-east-1, got %s", meta.Region)
	}
}

func TestNetfilterHelperFunctions(t *testing.T) {
	// Test verdict string conversion
	tests := []struct {
		name     string
		verdict  uint32
		expected string
	}{
		{"DROP", 0, "DROP"},
		{"ACCEPT", 1, "ACCEPT"},
		{"STOLEN", 2, "STOLEN"},
		{"QUEUE", 3, "QUEUE"},
		{"REPEAT", 4, "REPEAT"},
		{"STOP", 5, "STOP"},
		{"UNKNOWN", 999, "UNKNOWN_999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getVerdictString(tt.verdict)
			if result != tt.expected {
				t.Errorf("getVerdictString(%d) = %s; expected %s", tt.verdict, result, tt.expected)
			}
		})
	}

	// Test hook string conversion
	hookTests := []struct {
		name     string
		hook     uint32
		expected string
	}{
		{"PRE_ROUTING", 0, "NF_INET_PRE_ROUTING"},
		{"LOCAL_IN", 1, "NF_INET_LOCAL_IN"},
		{"FORWARD", 2, "NF_INET_FORWARD"},
		{"LOCAL_OUT", 3, "NF_INET_LOCAL_OUT"},
		{"POST_ROUTING", 4, "NF_INET_POST_ROUTING"},
		{"UNKNOWN", 999, "UNKNOWN_HOOK_999"},
	}

	for _, tt := range hookTests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHookString(tt.hook)
			if result != tt.expected {
				t.Errorf("getHookString(%d) = %s; expected %s", tt.hook, result, tt.expected)
			}
		})
	}
}

func TestCStringToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []int8
		expected string
	}{
		{
			name:     "simple string",
			input:    []int8{102, 105, 108, 116, 101, 114, 0}, // "filter"
			expected: "filter",
		},
		{
			name:     "empty string",
			input:    []int8{0},
			expected: "",
		},
		{
			name:     "string with embedded null",
			input:    []int8{116, 101, 115, 116, 0, 101, 120, 116, 114, 97},
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cStringToString(tt.input)
			if result != tt.expected {
				t.Errorf("cStringToString(%v) = %s; expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNetfilterInfoStructure(t *testing.T) {
	// Test that NetfilterInfo struct can be created and used
	info := NetfilterInfo{
		Verdict:    1, // ACCEPT
		Hook:       2, // FORWARD
		Priority:   -200,
		TableName:  [16]int8{102, 105, 108, 116, 101, 114, 0}, // "filter"
		ChainName:  [32]int8{70, 79, 82, 87, 65, 82, 68, 0},   // "FORWARD"
		RuleNum:    5,
		RuleTarget: [32]int8{65, 67, 67, 69, 80, 84, 0},                          // "ACCEPT"
		MatchInfo:  [64]int8{116, 99, 112, 32, 100, 112, 116, 58, 52, 52, 51, 0}, // "tcp dpt:443"
	}

	if info.Verdict != 1 {
		t.Errorf("Expected verdict 1, got %d", info.Verdict)
	}
	if info.Hook != 2 {
		t.Errorf("Expected hook 2, got %d", info.Hook)
	}
	if info.RuleNum != 5 {
		t.Errorf("Expected rule number 5, got %d", info.RuleNum)
	}

	// Test string conversion
	tableName := cStringToString(info.TableName[:])
	if tableName != "filter" {
		t.Errorf("Expected table name 'filter', got '%s'", tableName)
	}

	chainName := cStringToString(info.ChainName[:])
	if chainName != "FORWARD" {
		t.Errorf("Expected chain name 'FORWARD', got '%s'", chainName)
	}
}

func TestFlowStatsWithNetfilter(t *testing.T) {
	// Test that FlowStats with netfilter information can be created
	stats := FlowStats{
		Packets:     100,
		Bytes:       64000,
		LastVerdict: 1, // ACCEPT
		VerdictCount: map[uint32]uint32{
			0: 2,  // 2 DROPs
			1: 98, // 98 ACCEPTs
		},
		NetfilterInfo: NetfilterInfo{
			Verdict:    1,
			Hook:       2,
			Priority:   -200,
			TableName:  [16]int8{102, 105, 108, 116, 101, 114, 0}, // "filter"
			ChainName:  [32]int8{70, 79, 82, 87, 65, 82, 68, 0},   // "FORWARD"
			RuleNum:    3,
			RuleTarget: [32]int8{65, 67, 67, 69, 80, 84, 0}, // "ACCEPT"
		},
	}

	if stats.LastVerdict != 1 {
		t.Errorf("Expected last verdict 1, got %d", stats.LastVerdict)
	}
	if stats.VerdictCount[1] != 98 {
		t.Errorf("Expected 98 ACCEPT verdicts, got %d", stats.VerdictCount[1])
	}
	if stats.NetfilterInfo.RuleNum != 3 {
		t.Errorf("Expected rule number 3, got %d", stats.NetfilterInfo.RuleNum)
	}
}

func TestGetVerdictCount(t *testing.T) {
	// Test getVerdictCount helper function
	verdictCount := map[uint32]uint32{
		0: 5,  // 5 DROPs
		1: 95, // 95 ACCEPTs
		3: 2,  // 2 QUEUEs
	}

	tests := []struct {
		name     string
		verdict  uint32
		expected uint32
	}{
		{"ACCEPT count", 1, 95},
		{"DROP count", 0, 5},
		{"QUEUE count", 3, 2},
		{"non-existent verdict", 999, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getVerdictCount(verdictCount, tt.verdict)
			if result != tt.expected {
				t.Errorf("getVerdictCount(%d) = %d; expected %d", tt.verdict, result, tt.expected)
			}
		})
	}

	// Test with nil map
	result := getVerdictCount(nil, 1)
	if result != 0 {
		t.Errorf("getVerdictCount(nil, 1) = %d; expected 0", result)
	}
}
