# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Netfilter Verdict Tracking** - Major enhancement for firewall analysis
  - Packet verdict capture (ACCEPT, DROP, REJECT, QUEUE, REPEAT, STOP)
  - Netfilter hook identification (PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING)
  - iptables table and chain information (filter, nat, mangle, raw)
  - Rule number and target tracking when available
  - Verdict count statistics aggregated per flow
  - Match criteria information extraction
  - Integration with existing flow cache system
  - **Flattened output format**: Verdict counts as individual fields instead of nested objects

- **AWS Development Environment** - Complete setup automation for eBPF development
  - `./dev-setup.sh` - Interactive AWS EC2 instance creation and management
  - `scripts/setup-aws-dev.sh` - Automated AWS infrastructure provisioning
  - `scripts/setup-remote-env.sh` - eBPF development toolchain installation
  - `scripts/sync-to-remote.sh` - Local to remote code synchronization
  - Enhanced Makefile with AWS-aware build targets and detection
  - Comprehensive documentation for macOS/Windows developers

- **Comprehensive TCP Network Metrics** - Major enhancement to flow monitoring
  - Connection establishment latency tracking (3-way handshake timing)
  - Packet retransmission detection and classification (fast vs timeout retransmits)
  - Network jitter calculation from inter-packet arrival times
  - TCP window size monitoring (min/max/current)
  - Round-trip time (RTT) measurements with statistics
  - Out-of-order packet detection
  - Duplicate ACK counting for congestion analysis
  - ECN (Explicit Congestion Notification) flag tracking

### Changed
- **Output Format Version** - Bumped to version "3" to indicate netfilter capability
  - All netfilter fields included in unified JSON output
  - Netfilter fields apply to **all protocols** (TCP, UDP, etc.) since netfilter operates at IP level
  - Netfilter fields set to `null` only when no netfilter events captured for a flow
  - **Flattened verdict counts**: Individual metrics (`netfilter_accepts`, `netfilter_drops`, `netfilter_rejects`, `netfilter_queues`) instead of nested data
  - TCP-specific metrics set to `null` for non-TCP protocols (UDP, ICMP, etc.)
  - Comprehensive hook and rule information when available

- **eBPF Program Architecture** - Enhanced with netfilter integration
  - Added netfilter hook program (`SEC("netfilter")`) for verdict capture
  - Enhanced flow statistics structure with netfilter data fields
  - Improved flow cache with verdict tracking and count aggregation
  - Kernel version requirements: Linux 5.3+ with CONFIG_BPF_NETFILTER=y

- **Flow Cache Architecture** - Redesigned output system for unified metrics
  - Single JSON output per flow with all available metrics (including netfilter)
  - Intelligent null value handling for non-applicable metrics
  - Periodic output system (5-second intervals) instead of immediate logging
  - Flow aging with final metric output before expiration
  - Memory-efficient cache management with automatic cleanup

### Enhanced Features
- **Firewall Analysis**: Deep insight into packet filtering decisions for all protocols
- **Security Monitoring**: Comprehensive verdict tracking for security analysis across TCP, UDP, and other IP protocols
- **Protocol-Specific Metrics**: Proper null handling - only TCP metrics are null for non-TCP, netfilter applies to all
- **Flow Quality**: Combined network and firewall metrics in single output
- **Cross-platform Development**: Full AWS development environment for non-Linux systems

## Previous Features

### Added
- Initial release of FFFA flow monitoring tool
- eBPF/XDP-based packet capture for high performance
- AWS metadata enrichment with IMDSv2 support
- GENEVE tunnel support for encapsulated traffic
- Basic TCP flow tracking with flag monitoring
- Ring buffer for efficient event streaming
- AWS VPC Flow Log compatible output format
- Flow aging and cleanup to prevent memory leaks
- Comprehensive documentation and examples

### Features
- **Flow Monitoring**: Real-time network flow tracking using eBPF/XDP
- **AWS Integration**: Automatic EC2 instance metadata enrichment
- **Encapsulation Support**: GENEVE tunnel traffic analysis
- **Protocol Support**: TCP and UDP flow tracking
- **Performance**: Minimal overhead packet processing
- **Output Format**: AWS VPC Flow Log compatible format

### Technical Details
- eBPF program for kernel-space packet processing
- Go userspace program for flow collection and enrichment
- Ring buffer communication between kernel and userspace
- IMDSv2 for secure AWS metadata retrieval
- Flow table with configurable aging

## [1.0.0] - TBD

### Added
- Initial stable release

---

## Template for Future Releases

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Bug fixes

### Security
- Security fixes and improvements
