# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in FFFA, please report it responsibly:

### Preferred Method
Send an email to the project maintainers with:
- A description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact assessment
- Suggested fixes (if you have them)

### What to Include
- **Detailed description** of the vulnerability
- **Environment details** (OS, kernel version, etc.)
- **Proof of concept** code (if applicable)
- **Potential impact** on users

### What NOT to Include
- Do not open public issues for security vulnerabilities
- Do not include actual exploitation code in public communications

## Security Considerations

### eBPF Program Security
- The eBPF program runs in kernel space with restricted capabilities
- BPF verifier ensures memory safety and prevents infinite loops
- No user data is directly accessible from the eBPF program
- All packet accesses are bounds-checked

### Userspace Program Security
- Requires root privileges for eBPF program loading
- Uses IMDSv2 for secure AWS metadata retrieval
- No sensitive data is logged by default
- Ring buffer events contain only network flow metadata

### AWS Permissions
- Only requires access to Instance Metadata Service (IMDS)
- No additional IAM permissions needed
- Metadata is retrieved using IMDSv2 with session tokens

### Data Privacy
- Only network flow metadata is collected
- No packet payloads are captured
- AWS metadata is public instance information
- Flow logs contain only connection 5-tuples

## Best Practices

### Deployment
- Run with minimal necessary privileges
- Use dedicated service accounts
- Monitor for unusual resource usage
- Implement log rotation for output

### Network Security
- Ensure IMDS access is properly configured
- Consider network policies for metadata access
- Monitor for unauthorized eBPF program loading

### Monitoring
- Monitor for unexpected network traffic patterns
- Watch for high memory or CPU usage
- Set up alerts for program failures

## Vulnerability Response Process

1. **Acknowledgment**: We'll acknowledge receipt within 48 hours
2. **Assessment**: Initial assessment within 5 business days
3. **Fix Development**: Work on fixes with appropriate urgency
4. **Disclosure**: Coordinate disclosure timeline
5. **Release**: Security patches released as soon as possible

## Security Updates

Security updates will be:
- Released as patch versions (e.g., 1.0.1)
- Documented in the changelog
- Announced in release notes
- Tagged with security labels

## Contact

For security-related questions or concerns:
- Create a private issue (if platform supports it)
- Email project maintainers directly
- Use encrypted communication when possible

Thank you for helping keep FFFA secure!
