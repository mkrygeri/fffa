# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- **Flow Cache Architecture** - Redesigned output system for unified metrics
  - Single JSON output per flow with all available metrics
  - Intelligent null value handling for non-applicable metrics
  - Periodic output system (5-second intervals) instead of immediate logging
  - Flow aging with final metric output before expiration
  - Memory-efficient cache management with automatic cleanup
- **Output Format** - Unified JSON structure for all protocols
  - TCP flows include all network quality metrics
  - UDP/other protocols have TCP-specific fields set to null
  - Added flow timing information (first_seen, last_seen, duration_ms)
  - Eliminated separate specialized log lines in favor of comprehensive JSON

### Enhanced Features
- **Flow Monitoring**: Enhanced real-time network flow tracking with quality metrics
- **Performance Analysis**: Deep insight into network performance characteristics
- **Congestion Detection**: Multiple indicators for network congestion and quality issues
- **Connection Quality**: Detailed TCP connection health and performance metrics
- **Memory Management**: Efficient flow cache with automatic aging and cleanup

### Technical Improvements
- Extended eBPF program with additional maps for connection tracking
- Enhanced Go userspace with metric calculation and formatting
- Improved packet parsing for both native and encapsulated traffic
- Flow cache system with intelligent metric aggregation
- Null-safe JSON output formatting

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
