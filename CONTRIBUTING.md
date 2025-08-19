# Contributing to FFFA

Thank you for your interest in contributing to FFFA! This document provides guidelines and information for contributors.

## Code of Conduct

Please note that this project adheres to a Code of Conduct. By participating in this project, you agree to abide by its terms.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected vs actual behavior
4. Your environment (OS, kernel version, Go version)
5. Any relevant logs or error messages

### Suggesting Features

For feature requests:

1. Check if the feature already exists or is planned
2. Create an issue describing the feature
3. Explain the use case and benefits
4. Provide implementation ideas if you have them

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Ensure tests pass: `make test`
5. Ensure code builds: `make all`
6. Run `gofmt` on your code
7. Commit with a descriptive message
8. Push to your fork
9. Create a pull request

### Development Setup

1. **Prerequisites:**
   - Go 1.19+
   - Clang/LLVM
   - Kernel headers
   - libbpf development files

2. **Clone and build:**
   ```bash
   git clone https://github.com/your-username/fffa.git
   cd fffa
   make all
   ```

3. **Testing:**
   ```bash
   # Build and basic validation
   make clean && make all
   
   # Run with debug output
   sudo ./flowmonitor
   ```

## Code Style

### Go Code
- Follow standard Go formatting (`gofmt`)
- Use meaningful variable and function names
- Add comments for public functions and complex logic
- Handle errors appropriately

### eBPF Code
- Follow Linux kernel coding style
- Use appropriate BPF helper functions
- Minimize stack usage
- Add comments for complex packet parsing logic

### Commit Messages
- Use present tense ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Reference issues when applicable
- Use conventional commit format when possible:
  ```
  feat: add TCP flag tracking
  fix: correct endianness in port parsing
  docs: update installation instructions
  ```

## Architecture Guidelines

### eBPF Program (`bpf/flow_monitor.c`)
- Keep the program as simple as possible
- Avoid complex loops that might cause verifier issues
- Use appropriate map types for performance
- Validate all packet accesses against `data_end`

### Go Userspace (`main.go`)
- Handle ring buffer events efficiently
- Implement proper error handling
- Use appropriate logging levels
- Keep AWS metadata fetching lightweight

## Testing

### Manual Testing
- Test on different kernel versions when possible
- Verify with both native and encapsulated traffic
- Test AWS metadata enrichment on EC2 instances
- Check for memory leaks during extended runs

### Automated Testing
- Ensure CI passes on all supported Go versions
- Add unit tests for new utility functions
- Integration tests should be runnable in CI environment

## Performance Considerations

- eBPF programs should have minimal performance impact
- Avoid frequent allocations in hot paths
- Use efficient data structures
- Consider ring buffer sizing for high-traffic scenarios

## Documentation

- Update README.md for user-facing changes
- Add inline code comments for complex logic
- Update build instructions if dependencies change
- Document any new configuration options

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create a git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. GitHub Actions will create the release automatically

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Create a new issue with the "question" label
3. Be specific about what you're trying to achieve

Thank you for contributing to FFFA!
