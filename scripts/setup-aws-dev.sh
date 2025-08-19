#!/bin/bash
# Setup script for AWS EC2 development environment for eBPF

set -e

# Configuration
INSTANCE_TYPE="t3.medium"  # Sufficient for eBPF development
AMI_ID="ami-0c02fb55956c7d316"  # Amazon Linux 2023 (update as needed)
KEY_NAME="ebpf-dev-key"
SECURITY_GROUP="ebpf-dev-sg"
REGION="us-west-2"

echo "Setting up AWS EC2 instance for eBPF development..."

# Create key pair if it doesn't exist
if ! aws ec2 describe-key-pairs --key-names $KEY_NAME --region $REGION &>/dev/null; then
    echo "Creating SSH key pair..."
    aws ec2 create-key-pair --key-name $KEY_NAME --region $REGION --query 'KeyMaterial' --output text > ~/.ssh/${KEY_NAME}.pem
    chmod 400 ~/.ssh/${KEY_NAME}.pem
    echo "SSH key saved to ~/.ssh/${KEY_NAME}.pem"
fi

# Create security group if it doesn't exist
if ! aws ec2 describe-security-groups --group-names $SECURITY_GROUP --region $REGION &>/dev/null; then
    echo "Creating security group..."
    aws ec2 create-security-group --group-name $SECURITY_GROUP --description "eBPF development security group" --region $REGION
    
    # Allow SSH access
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP --protocol tcp --port 22 --cidr 0.0.0.0/0 --region $REGION
    
    # Allow HTTP/HTTPS for package downloads
    aws ec2 authorize-security-group-egress --group-name $SECURITY_GROUP --protocol tcp --port 80 --cidr 0.0.0.0/0 --region $REGION
    aws ec2 authorize-security-group-egress --group-name $SECURITY_GROUP --protocol tcp --port 443 --cidr 0.0.0.0/0 --region $REGION
fi

# Launch EC2 instance
echo "Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id $AMI_ID \
    --count 1 \
    --instance-type $INSTANCE_TYPE \
    --key-name $KEY_NAME \
    --security-groups $SECURITY_GROUP \
    --region $REGION \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=eBPF-Dev},{Key=Project,Value=FFFA}]' \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "Instance ID: $INSTANCE_ID"

# Wait for instance to be running
echo "Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region $REGION

# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $REGION --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "Instance is running at: $PUBLIC_IP"
echo "SSH command: ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$PUBLIC_IP"

# Create connection script
cat > connect-aws-dev.sh << EOF
#!/bin/bash
ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$PUBLIC_IP
EOF

chmod +x connect-aws-dev.sh

echo "Connection script created: ./connect-aws-dev.sh"
echo "Run './connect-aws-dev.sh' to connect to your development instance"
