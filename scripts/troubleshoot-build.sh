#!/bin/bash
# eBPF Build Troubleshooting Script
# Run this on your AWS EC2 instance to diagnose build issues

echo "=============================================="
echo "FFFA eBPF Build Troubleshooting Diagnostics"
echo "=============================================="
echo ""

# Check basic environment
echo "1. Basic Environment Check:"
echo "   Kernel version: $(uname -r)"
echo "   OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "   Architecture: $(uname -m)"
echo ""

# Check required tools
echo "2. Required Tools Check:"
for tool in clang llvm-config bpftool go make; do
    if command -v $tool &> /dev/null; then
        echo "   ✅ $tool: $(which $tool)"
        case $tool in
            clang) echo "      Version: $(clang --version | head -1)" ;;
            go) echo "      Version: $(go version)" ;;
        esac
    else
        echo "   ❌ $tool: NOT FOUND"
    fi
done
echo ""

# Check kernel headers
echo "3. Kernel Headers Check:"
KERNEL_VERSION=$(uname -r)
if [ -f "/usr/include/linux/bpf.h" ]; then
    echo "   ✅ /usr/include/linux/bpf.h exists"
else
    echo "   ❌ /usr/include/linux/bpf.h missing"
    echo "   Try: sudo dnf install -y kernel-headers kernel-devel"
fi

if [ -d "/lib/modules/$KERNEL_VERSION/build" ]; then
    echo "   ✅ Kernel build directory exists: /lib/modules/$KERNEL_VERSION/build"
else
    echo "   ❌ Kernel build directory missing: /lib/modules/$KERNEL_VERSION/build"
    echo "   Try: sudo dnf install -y kernel-devel-$KERNEL_VERSION"
fi
echo ""

# Check libbpf
echo "4. libbpf Check:"
if [ -f "/usr/lib64/libbpf.so" ] || [ -f "/usr/local/lib64/libbpf.so" ] || [ -f "/usr/lib/libbpf.so" ]; then
    echo "   ✅ libbpf library found"
else
    echo "   ❌ libbpf library missing"
    echo "   Try: sudo dnf install -y libbpf-devel"
fi

if [ -f "/usr/include/bpf/bpf.h" ] || [ -f "/usr/local/include/bpf/bpf.h" ]; then
    echo "   ✅ libbpf headers found"
else
    echo "   ❌ libbpf headers missing"
    echo "   Try: sudo dnf install -y libbpf-devel"
fi
echo ""

# Check if we're in FFFA directory
echo "5. Project Directory Check:"
if [ -f "Makefile" ] && [ -f "main.go" ] && [ -d "bpf" ]; then
    echo "   ✅ In FFFA project directory"
    echo "   ✅ Makefile exists"
    echo "   ✅ main.go exists"
    echo "   ✅ bpf/ directory exists"
    
    if [ -f "bpf/flow_monitor.c" ]; then
        echo "   ✅ bpf/flow_monitor.c exists"
    else
        echo "   ❌ bpf/flow_monitor.c missing"
    fi
else
    echo "   ❌ Not in FFFA project directory or files missing"
    echo "   Make sure you're in the fffa directory and have cloned the repo"
fi
echo ""

# Test simple compilation
echo "6. Test Simple eBPF Compilation:"
cat > /tmp/test_bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int test_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
EOF

echo "   Testing basic eBPF compilation..."
if clang -O2 -target bpf -c /tmp/test_bpf.c -o /tmp/test_bpf.o 2>/tmp/clang_error.log; then
    echo "   ✅ Basic eBPF compilation works"
    rm -f /tmp/test_bpf.o /tmp/test_bpf.c
else
    echo "   ❌ Basic eBPF compilation failed"
    echo "   Error details:"
    cat /tmp/clang_error.log | sed 's/^/      /'
fi
rm -f /tmp/clang_error.log /tmp/test_bpf.c
echo ""

# Show make targets
echo "7. Available Make Targets:"
if [ -f "Makefile" ]; then
    echo "   Available targets in Makefile:"
    grep "^[a-zA-Z][a-zA-Z0-9_-]*:" Makefile | cut -d: -f1 | sed 's/^/      /'
else
    echo "   ❌ No Makefile found"
fi
echo ""

echo "=============================================="
echo "Troubleshooting Complete!"
echo ""
echo "Common Solutions:"
echo "1. Missing headers: sudo dnf install -y kernel-headers-\$(uname -r) kernel-devel-\$(uname -r)"
echo "2. Missing libbpf: sudo dnf install -y libbpf-devel"
echo "3. Old clang: sudo dnf install -y clang llvm"
echo "4. Path issues: source ~/.bashrc"
echo ""
echo "To get detailed build error, run:"
echo "   make build-bpf 2>&1 | tee build.log"
echo ""
echo "Then share the contents of build.log for specific help."
echo "=============================================="
