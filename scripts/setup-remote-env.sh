#!/bin/bash
# Remote setup script for eBPF development environment
# Run this on the AWS EC2 instance after connecting

set -e

echo "Setting up eBPF development environment on Amazon Linux..."

# Update system
sudo dnf update -y

# Install development tools
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    kernel-headers \
    bpftool \
    git \
    golang \
    make \
    wget \
    curl

# Install specific eBPF tools
echo "Installing additional eBPF tools..."

# Install newer Go version if needed
GO_VERSION="1.21.5"
if ! go version | grep -q $GO_VERSION; then
    echo "Installing Go $GO_VERSION..."
    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go${GO_VERSION}.linux-amd64.tar.gz
fi

# Install libbpf from source for latest features
echo "Installing libbpf from source..."
cd /tmp
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
sudo make install

# Install BCC tools for debugging
echo "Installing BCC tools..."
sudo dnf install -y bcc-tools python3-bcc

# Verify installations
echo "Verifying installations..."
clang --version
llvm-config --version
bpftool version
go version

# Create development directory
mkdir -p ~/fffa-dev
cd ~/fffa-dev

echo "Development environment setup complete!"
echo ""
echo "=================== NEXT STEPS ==================="
echo "Clone your FFFA repository and start development:"
echo "  git clone https://github.com/mkrygeri/fffa.git"
echo "  cd fffa"
echo ""
echo "Before building, verify your environment:"
echo "  make help                    # Show available targets"
echo "  which clang                  # Should show /usr/bin/clang"
echo "  ls /usr/include/linux/bpf.h  # Should exist"
echo "  uname -r                     # Show kernel version"
echo ""
echo "Build eBPF program:"
echo "  make build-bpf               # Build eBPF object file"
echo ""
echo "If build fails, try:"
echo "  sudo dnf install -y kernel-headers-\$(uname -r)"
echo "  sudo dnf install -y kernel-devel-\$(uname -r)"
echo ""
echo "==============================================="
