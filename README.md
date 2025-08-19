# FFFA - Flow Monitoring with eBPF

A high-performance network flow monitoring tool that uses eBPF/XDP to capture and analyze network traffic on AWS EC2 instances. The tool provides AWS VPC Flow Log-style enrichment with support for both native and GENEVE-encapsulated traffic.

## Features

- **eBPF/XDP-based packet capture** for minimal overhead
- **AWS metadata enrichment** with IMDSv2 support
- **GENEVE tunnel support** for encapsulated traffic
- **Comprehensive TCP metrics** including:
  - Connection establishment latency (3-way handshake timing)
  - Packet retransmission detection (fast retransmits vs timeouts)
  - Network jitter calculation
  - TCP window size tracking
  - Round-trip time (RTT) measurements
  - Out-of-order packet detection
  - Duplicate ACK counting
  - ECN (Explicit Congestion Notification) flag tracking
- **Ring buffer** for efficient event streaming
- **Enhanced flow log output** with JSON structured metrics
- **AWS VPC Flow Log compatible output**

## Architecture

The project consists of two main components:

1. **eBPF Program** (`bpf/flow_monitor.c`) - Kernel-space packet processing
2. **Go Userspace** (`main.go`) - User-space flow collection and AWS enrichment

## Prerequisites

- Linux kernel 4.18+ with eBPF support
- Go 1.19+
- Clang/LLVM for eBPF compilation
- Kernel headers for your running kernel
- AWS EC2 instance with appropriate IAM permissions

### Installing Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) build-essential
```

#### Amazon Linux 2
```bash
sudo yum install clang llvm kernel-devel-$(uname -r) make
```

## Building

1. Clone the repository:
```bash
git clone https://github.com/mkrygeri/fffa.git
cd fffa
```

2. Build the project:
```bash
make
```

This will:
- Compile the eBPF program to `fffa.bpf.o`
- Build the Go userspace program to `flowmonitor`

## Usage

### Basic Usage

Run the flow monitor (requires root privileges):

```bash
sudo ./flowmonitor
```

### Configuration

The program uses several constants that can be modified in `main.go`:

- `IfaceName`: Network interface to monitor (default: "ens5")
- `RefreshInterval`: AWS metadata refresh interval (default: 5 minutes)

### Flow Cache Behavior

FFFA uses an intelligent flow cache system that aggregates metrics:

- **Flow Identification**: Flows are identified by 5-tuple (src/dst IP/port + protocol)
- **Metric Aggregation**: All metrics are continuously updated in the cache
- **Periodic Output**: Complete flow metrics are output every 5 seconds
- **Flow Aging**: Inactive flows are expired after 60 seconds with final output
- **Null Values**: Metrics that don't apply (e.g., TCP metrics for UDP) are set to null
- **Memory Efficiency**: Flow state is automatically cleaned up to prevent memory leaks

### Output Format

The tool outputs comprehensive flow logs with all available metrics in a single JSON entry per flow. Metrics that don't apply to a particular protocol or haven't been measured are set to `null`.

**Unified JSON Format (all flows):**
```json
{
  "version": "3",
  "timestamp": "2023-08-19T10:30:00Z",
  "proto": "TCP",
  "src_ip": "10.0.1.100",
  "src_port": 8080,
  "dst_ip": "10.0.1.200", 
  "dst_port": 443,
  "direction": 0,
  "encapsulated": true,
  "packets": 150,
  "bytes": 65536,
  "first_seen": "2023-08-19T10:29:50Z",
  "last_seen": "2023-08-19T10:30:00Z",
  "duration_ms": 10000,
  "tcp_flags": "SYN|ACK|PSH",
  "handshake_latency_us": 5000,
  "retransmissions": 2,
  "fast_retransmits": 1,
  "timeout_retransmits": 1,
  "avg_jitter_us": 1500,
  "max_jitter_us": 8000,
  "min_window_size": 1024,
  "max_window_size": 65535,
  "out_of_order_pkts": 3,
  "duplicate_acks": 5,
  "min_rtt_us": 2000,
  "max_rtt_us": 15000,
  "avg_rtt_us": 7500,
  "rtt_samples": 25,
  "ecn_flags": 1,
  "aws_account": "123456789012",
  "aws_vpc": "vpc-12345678",
  "aws_subnet": "subnet-87654321"
}
```

**UDP Flow Example (TCP metrics are null):**
```json
{
  "version": "3",
  "proto": "UDP",
  "src_ip": "10.0.1.100",
  "src_port": 53,
  "packets": 10,
  "bytes": 512,
  "tcp_flags": null,
  "handshake_latency_us": null,
  "retransmissions": null,
  "avg_jitter_us": null,
  "min_rtt_us": null,
  "aws_account": "123456789012"
}
```

### Fields Explanation

**Basic Flow Fields:**
- `proto`: Protocol (TCP/UDP)
- `src_ip/src_port`: Outer packet source (for encapsulated traffic)
- `dst_ip/dst_port`: Outer packet destination
- `pkt_src_ip/pkt_dst_ip`: Inner packet source/destination
- `direction`: 0=ingress, 1=egress
- `encapsulated`: Whether traffic is GENEVE encapsulated
- `packets/bytes`: Packet and byte counts
- `first_seen/last_seen`: Flow start and end timestamps
- `duration_ms`: Flow duration in milliseconds

**TCP Metrics (null for non-TCP protocols):**
- `tcp_flags`: Human-readable TCP flags (SYN|ACK|FIN|etc.)
- `handshake_latency_us`: 3-way handshake completion time (null if not measured)
- `retransmissions`: Total retransmitted packets
- `fast_retransmits`: Fast retransmit algorithm triggers
- `timeout_retransmits`: Timeout-based retransmissions
- `avg_jitter_us/max_jitter_us`: Network jitter measurements (null if not calculated)
- `min/max_window_size`: TCP window size range (null if not observed)
- `last_window_size`: Most recent window size
- `out_of_order_pkts`: Packets received out of sequence
- `duplicate_acks`: Duplicate ACK count (congestion indicator)
- `min/max/avg_rtt_us`: Round-trip time measurements (null if not measured)
- `rtt_samples`: Number of RTT samples collected
- `ecn_flags`: ECN congestion notification flags

**AWS Metadata:**
- `aws_account/vpc/subnet/instance/az/region`: AWS infrastructure context

## AWS Permissions

The EC2 instance needs access to the Instance Metadata Service (IMDS). No additional IAM permissions are required as the tool uses IMDSv2 for metadata retrieval.

## Development

### Project Structure

```
FFFA/
├── main.go              # Go userspace program
├── Makefile            # Build configuration
├── bpf/
│   └── flow_monitor.c  # eBPF kernel program
└── remote/
    └── bpf/
        └── flow_monitor.c  # Remote/backup eBPF program
```

### Building for Development

```bash
# Clean build artifacts
make clean

# Build everything
make all

# Build only eBPF program
make fffa.bpf.o

# Build only Go program
make flowmonitor
```

### Debugging

Enable debug output by modifying the code or use:

```bash
# View eBPF program logs
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Check for eBPF verifier issues
dmesg | grep bpf
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with `sudo`
2. **Interface not found**: Update `IfaceName` in `main.go`
3. **eBPF compilation errors**: Ensure kernel headers are installed
4. **AWS metadata fetch errors**: Verify IMDSv2 is enabled

### Kernel Requirements

- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_XDP_SOCKETS=y (for XDP support)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests if applicable
5. Commit your changes: `git commit -am 'Add feature'`
6. Push to the branch: `git push origin feature-name`
7. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

- The eBPF program uses GPL license as required for kernel code
- IMDSv2 is used for secure metadata retrieval
- No sensitive data is logged or transmitted

## Performance

- Minimal overhead due to eBPF/XDP processing
- Ring buffer for efficient event delivery
- Flow aging to prevent memory leaks
- Configurable flow timeout (default: 60 seconds)

## Limitations

- Currently supports IPv4 traffic only
- GENEVE encapsulation support (port 6081)
- AWS-specific metadata enrichment
- Requires root privileges for eBPF program loading
