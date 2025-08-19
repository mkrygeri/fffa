#!/bin/bash
# Quick start script for eBPF development on AWS

set -e

echo "FFFA eBPF Development Setup"
echo "=========================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install it first:"
    echo "   brew install awscli"
    echo "   aws configure"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured. Run:"
    echo "   aws configure"
    exit 1
fi

echo "✅ AWS CLI configured"

# Check if scripts directory exists
if [ ! -d "scripts" ]; then
    echo "❌ Please run this from the FFFA project root directory"
    exit 1
fi

echo "✅ In FFFA project directory"

# Make scripts executable
chmod +x scripts/*.sh

echo ""
echo "Choose an option:"
echo "1. Create new AWS development instance"
echo "2. Connect to existing instance"
echo "3. Show connection info"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "Creating AWS development instance..."
        ./scripts/setup-aws-dev.sh
        ;;
    2)
        read -p "Enter instance IP address: " ip
        echo "Connecting to $ip..."
        ssh -i ~/.ssh/ebpf-dev-key.pem ec2-user@$ip
        ;;
    3)
        echo ""
        echo "Connection Information:"
        echo "======================"
        echo "SSH Key: ~/.ssh/ebpf-dev-key.pem"
        echo "User: ec2-user"
        echo ""
        echo "To connect manually:"
        echo "  ssh -i ~/.ssh/ebpf-dev-key.pem ec2-user@<instance-ip>"
        echo ""
        echo "To sync project:"
        echo "  ./scripts/sync-to-remote.sh ec2-user@<instance-ip>"
        echo ""
        echo "Setup remote environment:"
        echo "  curl -O https://raw.githubusercontent.com/mkrygeri/fffa/main/scripts/setup-remote-env.sh"
        echo "  chmod +x setup-remote-env.sh"
        echo "  ./setup-remote-env.sh"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac
