# FFFA - Flow Monitoring with eBPF

A high-performance network flow monitoring tool that uses eBPF/XDP to capture and analyze network traffic on AWS EC2 instances. The tool provides AWS VPC Flow Log-style enrichment with support for both native and GENEVE-encapsulated traffic.

## Features

- **eBPF/XDP-based packet capture** for minimal overhead
- **AWS metadata enrichment** with IMDSv2 support
- **GENEVE tunnel support** for encapsulated traffic
- **TCP flow tracking** with flag monitoring
- **Ring buffer** for efficient event streaming
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
git clone <your-repo-url>
cd FFFA
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

### Output Format

The tool outputs flow logs in a format compatible with AWS VPC Flow Logs:

```
flowlog version=2 proto=TCP src=10.0.1.100:8080 dst=10.0.1.200:443 pkt-src=192.168.1.10 pkt-dst=192.168.1.20 direction=0 encapsulated=true account=123456789012 vpc=vpc-12345678 subnet=subnet-87654321 instance=i-1234567890abcdef0 az=us-east-1a region=us-east-1 time=2023-08-19T10:30:00Z
```

### Fields Explanation

- `proto`: Protocol (TCP/UDP)
- `src/dst`: Outer packet source/destination (for encapsulated traffic)
- `pkt-src/pkt-dst`: Inner packet source/destination
- `direction`: 0=ingress, 1=egress
- `encapsulated`: Whether traffic is GENEVE encapsulated
- AWS metadata: Account, VPC, subnet, instance, AZ, region

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
