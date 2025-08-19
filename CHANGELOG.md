# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of FFFA flow monitoring tool
- eBPF/XDP-based packet capture for high performance
- AWS metadata enrichment with IMDSv2 support
- GENEVE tunnel support for encapsulated traffic
- TCP flow tracking with flag monitoring
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
