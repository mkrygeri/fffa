# eBPF Development on AWS

This directory contains scripts to set up a remote AWS EC2 development environment for building and testing eBPF programs.

## Quick Start

1. **Setup AWS Instance**:
   ```bash
   cd scripts
   chmod +x setup-aws-dev.sh
   ./setup-aws-dev.sh
   ```

2. **Connect to Instance**:
   ```bash
   ./connect-aws-dev.sh
   ```

3. **Setup Development Environment** (run on remote):
   ```bash
   curl -O https://raw.githubusercontent.com/mkrygeri/fffa/main/scripts/setup-remote-env.sh
   chmod +x setup-remote-env.sh
   ./setup-remote-env.sh
   ```

4. **Sync Project Files**:
   ```bash
   # From local machine
   ./sync-to-remote.sh ec2-user@<instance-ip>
   ```

## Scripts

- `setup-aws-dev.sh` - Creates EC2 instance with proper security groups
- `setup-remote-env.sh` - Installs eBPF development tools on remote instance  
- `sync-to-remote.sh` - Syncs local project to remote instance
- `connect-aws-dev.sh` - Generated script to connect to your instance

## Building eBPF on Remote

Once connected to the remote instance:

```bash
cd ~/fffa-dev/fffa
make build-bpf    # Build eBPF programs
sudo ./fffa       # Run with root privileges (required for eBPF)
```

## Cleanup

To terminate the AWS instance:
```bash
aws ec2 terminate-instances --instance-ids <instance-id> --region us-west-2
```

## Requirements

- AWS CLI configured with appropriate permissions
- SSH key pair will be created automatically
- Instance will be created in us-west-2 region (modify script to change)

## Security Notes

- Security group allows SSH access from anywhere (0.0.0.0/0)
- Consider restricting to your IP address for production use
- SSH key is saved to `~/.ssh/ebpf-dev-key.pem`
- Remember to terminate instances when not in use to avoid charges
