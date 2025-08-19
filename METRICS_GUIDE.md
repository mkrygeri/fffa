# Network Metrics Guide

This guide explains the comprehensive network metrics collected by FFFA and how to interpret them for network performance analysis.

## Metric Categories

### Connection Establishment Metrics

**Handshake Latency (`handshake_latency_us`)**
- Measures the time from initial SYN to final ACK completion
- Values in microseconds
- Typical ranges:
  - Local network: 100-1000 μs
  - Regional: 1000-10000 μs
  - Global: 10000-100000 μs
- High values indicate network congestion or routing issues

### Retransmission Analysis

**Total Retransmissions (`retransmissions`)**
- Count of all retransmitted packets
- Indicates packet loss or network reliability issues

**Fast Retransmits (`fast_retransmits`)**
- Retransmissions triggered by duplicate ACKs (< 200ms)
- Indicates temporary congestion or buffer overflows
- Generally recovers quickly

**Timeout Retransmits (`timeout_retransmits`)**
- Retransmissions after timeout (> 200ms)
- Indicates more serious network issues
- Can significantly impact application performance

### Jitter and Timing Metrics

**Average Jitter (`avg_jitter_us`)**
- Variation in inter-packet arrival times
- Lower values indicate more consistent network performance
- Typical ranges:
  - Excellent: < 1000 μs
  - Good: 1000-5000 μs
  - Poor: > 10000 μs

**Maximum Jitter (`max_jitter_us`)**
- Worst-case jitter observed
- Helps identify network stability issues

### Round-Trip Time (RTT) Metrics

**Minimum RTT (`min_rtt_us`)**
- Best-case round-trip time observed
- Represents base network latency

**Maximum RTT (`max_rtt_us`)**
- Worst-case round-trip time
- Indicates congestion or routing variations

**Average RTT (`avg_rtt_us`)**
- Mean round-trip time across all samples
- Primary indicator of connection latency

### Window Size Metrics

**Window Size Range (`min_window_size`, `max_window_size`)**
- TCP window size variations
- Indicates flow control and congestion management
- Shrinking windows suggest congestion

**Current Window Size (`last_window_size`)**
- Most recent advertised window size
- Real-time view of receive buffer availability

### Quality Indicators

**Out-of-Order Packets (`out_of_order_pkts`)**
- Packets received in wrong sequence
- Indicates network path variations or load balancing issues

**Duplicate ACKs (`duplicate_acks`)**
- Repeated acknowledgments for same data
- Triggers fast retransmit algorithms
- High counts indicate packet loss

**ECN Flags (`ecn_flags`)**
- Explicit Congestion Notification markers
- Proactive congestion signaling
- Values: 0=None, 1=ECT(1), 2=ECT(0), 3=CE

## Performance Thresholds

### Excellent Network Performance
- Handshake latency: < 5ms
- Retransmissions: < 0.1% of packets
- Jitter: < 1ms
- RTT variation: < 20% of minimum RTT

### Good Network Performance
- Handshake latency: 5-20ms
- Retransmissions: 0.1-1% of packets
- Jitter: 1-5ms
- RTT variation: 20-50% of minimum RTT

### Poor Network Performance
- Handshake latency: > 50ms
- Retransmissions: > 2% of packets
- Jitter: > 10ms
- RTT variation: > 100% of minimum RTT

## Troubleshooting Guide

### High Handshake Latency
- Check network routing
- Verify DNS resolution times
- Examine load balancer configuration
- Review firewall processing delays

### Excessive Retransmissions
- Monitor network utilization
- Check for faulty network equipment
- Verify MTU settings
- Examine buffer sizes

### High Jitter
- Look for network congestion
- Check for competing traffic flows
- Verify QoS configurations
- Examine network path stability

### Window Size Issues
- Monitor application receive buffer usage
- Check for slow consumers
- Verify network bandwidth limitations
- Examine congestion control algorithm behavior

## Monitoring Best Practices

1. **Baseline Establishment**
   - Collect metrics during normal operations
   - Establish performance baselines
   - Set appropriate alerting thresholds

2. **Trend Analysis**
   - Monitor metrics over time
   - Identify performance degradation patterns
   - Correlate with infrastructure changes

3. **Alert Configuration**
   - Set alerts for metric thresholds
   - Use percentage-based retransmission alerts
   - Monitor jitter spikes and RTT variations

4. **Correlation Analysis**
   - Compare metrics across different flows
   - Correlate with system resource usage
   - Examine relationships between different metric types

## Output Format Examples

### High-Performance Connection
```json
{
  "handshake_latency_us": 2000,
  "retransmissions": 0,
  "avg_jitter_us": 500,
  "avg_rtt_us": 3000,
  "out_of_order_pkts": 0
}
```

### Congested Connection
```json
{
  "handshake_latency_us": 25000,
  "retransmissions": 15,
  "fast_retransmits": 10,
  "timeout_retransmits": 5,
  "avg_jitter_us": 12000,
  "max_jitter_us": 50000,
  "avg_rtt_us": 45000,
  "duplicate_acks": 30,
  "out_of_order_pkts": 8
}
```

## Integration with Monitoring Systems

### Prometheus Metrics
- Convert JSON output to Prometheus format
- Create dashboards for key metrics
- Set up alerting rules

### ELK Stack Integration
- Index JSON logs in Elasticsearch
- Create Kibana visualizations
- Set up anomaly detection

### AWS CloudWatch
- Send metrics to CloudWatch
- Create custom dashboards
- Configure CloudWatch alarms
