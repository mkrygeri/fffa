#!/bin/bash
# Sync local FFFA project to remote AWS instance
# Usage: ./sync-to-remote.sh [remote-host]

set -e

REMOTE_HOST=${1:-""}
if [ -z "$REMOTE_HOST" ]; then
    echo "Usage: $0 <remote-host>"
    echo "Example: $0 ec2-user@1.2.3.4"
    exit 1
fi

KEY_FILE="~/.ssh/ebpf-dev-key.pem"
REMOTE_DIR="~/fffa-dev/fffa"

echo "Syncing FFFA project to $REMOTE_HOST:$REMOTE_DIR"

# Create remote directory
ssh -i $KEY_FILE $REMOTE_HOST "mkdir -p $REMOTE_DIR"

# Sync project files (excluding build artifacts and .git)
rsync -avz -e "ssh -i $KEY_FILE" \
    --exclude='.git' \
    --exclude='*.o' \
    --exclude='fffa' \
    --exclude='.vscode' \
    --exclude='remote/' \
    ./ $REMOTE_HOST:$REMOTE_DIR/

echo "Project synced successfully!"
echo "Connect and build with:"
echo "  ssh -i $KEY_FILE $REMOTE_HOST"
echo "  cd $REMOTE_DIR"
echo "  make build-bpf"
