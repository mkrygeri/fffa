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
