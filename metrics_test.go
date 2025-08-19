package main

import (
	"fmt"
	"testing"
	"time"
)

func TestFlowStatsStructure(t *testing.T) {
	// Test that FlowStats struct can be created and accessed
	stats := FlowStats{
		Packets:            100,
		Bytes:              15000,
		HandshakeLatencyUs: 5000, // 5ms
		Retransmissions:    2,
		FastRetransmits:    1,
		AvgJitterUs:        1000, // 1ms
		MaxJitterUs:        5000, // 5ms
		MinWindowSize:      1024,
		MaxWindowSize:      65535,
		MinRTTUs:           1000,  // 1ms
		MaxRTTUs:           50000, // 50ms
	}

	if stats.HandshakeLatencyUs != 5000 {
		t.Errorf("Expected handshake latency 5000, got %d", stats.HandshakeLatencyUs)
	}
	if stats.Retransmissions != 2 {
		t.Errorf("Expected 2 retransmissions, got %d", stats.Retransmissions)
	}
	if stats.AvgJitterUs != 1000 {
		t.Errorf("Expected avg jitter 1000, got %d", stats.AvgJitterUs)
	}
}

func TestCalculateAvgRTT(t *testing.T) {
	tests := []struct {
		name     string
		stats    FlowStats
		expected uint32
	}{
		{
			name: "no samples",
			stats: FlowStats{
				TotalRTTSamples: 0,
				SumRTTUs:        0,
			},
			expected: 0,
		},
		{
			name: "single sample",
			stats: FlowStats{
				TotalRTTSamples: 1,
				SumRTTUs:        5000,
			},
			expected: 5000,
		},
		{
			name: "multiple samples",
			stats: FlowStats{
				TotalRTTSamples: 4,
				SumRTTUs:        20000, // 5000 * 4
			},
			expected: 5000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateAvgRTT(&tt.stats)
			if result != tt.expected {
				t.Errorf("calculateAvgRTT() = %d; expected %d", result, tt.expected)
			}
		})
	}
}

func TestFormatTCPFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint8
		expected string
	}{
		{
			name:     "SYN flag",
			flags:    0x02,
			expected: "SYN",
		},
		{
			name:     "SYN+ACK flags",
			flags:    0x12, // SYN (0x02) + ACK (0x10)
			expected: "SYN|ACK",
		},
		{
			name:     "FIN+ACK flags",
			flags:    0x11, // FIN (0x01) + ACK (0x10)
			expected: "FIN|ACK",
		},
		{
			name:     "no flags",
			flags:    0x00,
			expected: "NONE",
		},
		{
			name:     "all flags",
			flags:    0xFF,
			expected: "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTCPFlags(tt.flags)
			if result != tt.expected {
				t.Errorf("formatTCPFlags(%x) = %s; expected %s", tt.flags, result, tt.expected)
			}
		})
	}
}

func TestFormatFlowMetricsJSON(t *testing.T) {
	key := FlowKey{
		OuterSrcIP:     0x0100007f, // 127.0.0.1
		OuterDstIP:     0x0200007f, // 127.0.0.2
		InnerSrcIP:     0x0100007f,
		InnerDstIP:     0x0200007f,
		InnerSrcPort:   8080,
		InnerDstPort:   443,
		InnerProto:     6, // TCP
		Direction:      0,
		IsEncapsulated: 0,
	}

	metrics := FlowStats{
		Packets:            100,
		Bytes:              15000,
		TCPFlags:           0x12, // SYN+ACK
		HandshakeLatencyUs: 5000,
		Retransmissions:    2,
		FastRetransmits:    1,
		AvgJitterUs:        1000,
		MaxJitterUs:        5000,
		MinWindowSize:      1024,
		MaxWindowSize:      65535,
		MinRTTUs:           1000,
		MaxRTTUs:           50000,
		TotalRTTSamples:    10,
		SumRTTUs:           50000,
	}

	entry := &FlowCacheEntry{
		Key:            key,
		FirstSeen:      time.Now().Add(-10 * time.Second),
		LastSeen:       time.Now(),
		Metrics:        metrics,
		MetricsUpdated: true,
	}

	metadata := InstanceMeta{
		AccountID:        "123456789012",
		InstanceID:       "i-1234567890abcdef0",
		Region:           "us-east-1",
		AvailabilityZone: "us-east-1a",
		VpcID:            "vpc-12345678",
		SubnetID:         "subnet-87654321",
	}

	ts := time.Now().Format(time.RFC3339)
	result := formatFlowMetricsJSON(entry, metadata, ts)

	// Basic validation that JSON is generated
	if len(result) == 0 {
		t.Error("formatFlowMetricsJSON returned empty string")
	}

	// Check that it contains expected fields
	expectedFields := []string{
		"version", "proto", "src_ip", "dst_ip", "handshake_latency_us",
		"retransmissions", "avg_jitter_us", "aws_account", "first_seen", "last_seen",
	}

	for _, field := range expectedFields {
		if !contains(result, field) {
			t.Errorf("JSON output missing field: %s", field)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsAt(s, substr, 1)))
}

func containsAt(s, substr string, start int) bool {
	if start >= len(s) {
		return false
	}
	if start+len(substr) <= len(s) && s[start:start+len(substr)] == substr {
		return true
	}
	return containsAt(s, substr, start+1)
}

func TestFlowCacheEntry(t *testing.T) {
	// Test that FlowCacheEntry can be created and managed
	key := FlowKey{
		InnerProto:   6, // TCP
		InnerSrcPort: 8080,
		InnerDstPort: 443,
	}

	now := time.Now()
	entry := &FlowCacheEntry{
		Key:            key,
		FirstSeen:      now,
		LastSeen:       now,
		Metrics:        FlowStats{Packets: 1},
		MetricsUpdated: true,
	}

	if entry.Key.InnerProto != 6 {
		t.Errorf("Expected TCP protocol (6), got %d", entry.Key.InnerProto)
	}
	if !entry.MetricsUpdated {
		t.Error("Expected MetricsUpdated to be true")
	}
	if entry.Metrics.Packets != 1 {
		t.Errorf("Expected 1 packet, got %d", entry.Metrics.Packets)
	}

	// Test updating the entry
	entry.LastSeen = now.Add(5 * time.Second)
	entry.Metrics.Packets = 10
	entry.MetricsUpdated = true

	duration := entry.LastSeen.Sub(entry.FirstSeen)
	if duration != 5*time.Second {
		t.Errorf("Expected 5 second duration, got %v", duration)
	}
}

func TestNullMetricsForNonTCP(t *testing.T) {
	// Test that UDP flows get null values for TCP-specific metrics
	key := FlowKey{
		InnerProto: 17, // UDP
	}

	entry := &FlowCacheEntry{
		Key:       key,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Metrics:   FlowStats{Packets: 5},
	}

	metadata := InstanceMeta{
		AccountID: "123456789012",
		VpcID:     "vpc-12345678",
	}

	result := formatFlowMetricsJSON(entry, metadata, time.Now().Format(time.RFC3339))

	// Check that TCP-specific fields are null for UDP
	tcpSpecificFields := []string{
		"tcp_flags", "handshake_latency_us", "retransmissions",
		"avg_jitter_us", "min_window_size", "min_rtt_us",
	}

	for _, field := range tcpSpecificFields {
		if !contains(result, fmt.Sprintf(`"%s":null`, field)) {
			t.Errorf("Expected %s to be null for UDP flow, but found in: %s", field, result)
		}
	}
}
