# EKS Patching Workflow Troubleshooting Guide

## Common Issues and Solutions

### 1. Cluster Access Issues

#### Problem
`Error: Unable to access EKS cluster`

#### Symptoms
- Step Functions execution fails at cluster discovery
- Lambda functions return authentication errors
- kubectl commands fail with authentication issues

#### Solutions
```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name your-cluster-name

# Verify IAM role mapping
kubectl describe configmap aws-auth -n kube-system

# Check IAM permissions
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::account:role/EKSPatchingRole --resource-arns '*' --action-names 'eks:*'
```

### 2. Node Draining Failures

#### Problem
`Nodes fail to drain properly during patching`

#### Symptoms
- Pods remain stuck in terminating state
- Drain operation times out
- Workloads not rescheduling to other nodes

#### Solutions
```bash
# Force drain with grace period
kubectl drain node-name --ignore-daemonsets --delete-emptydir-data --force --grace-period=0

# Check pod disruption budgets
kubectl get pdb --all-namespaces

# Verify node taints and cordons
kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints
```

### 3. SSM Agent Connectivity

#### Problem
`SSM automation documents fail to execute`

#### Symptoms
- Patch operations timeout
- No response from target instances
- SSM Run Command shows "Failed" status

#### Solutions
```bash
# Verify SSM agent status
sudo systemctl status amazon-ssm-agent

# Check instance IAM role
aws iam get-role --role-name EC2-SSM-Role

# Test SSM connectivity
aws ssm send-command --instance-ids i-1234567890abcdef0 --document-name "AWS-RunShellScript" --parameters 'commands=["echo hello"]'
```

### 4. Step Functions Execution Failures

#### Problem
`Step Functions state machine executions fail`

#### Symptoms
- State transitions fail with timeout
- Lambda function invocations return errors
- Execution history shows failed states

#### Solutions
```bash
# Check execution logs
aws logs filter-log-events --log-group-name /aws/stepfunctions/EKSPatchingOrchestrator

# Verify Lambda function permissions
aws lambda get-policy --function-name eks-patching-coordinator

# Review state machine definition
aws stepfunctions describe-state-machine --state-machine-arn your-state-machine-arn
```

### 5. Patching Window Issues

#### Problem
`Maintenance windows not respected`

#### Symptoms
- Patching starts outside defined windows
- Operations continue beyond window end time
- Scheduling conflicts with business hours

#### Solutions
```json
{
  "maintenanceWindow": {
    "startTime": "02:00",
    "endTime": "04:00",
    "timezone": "America/New_York",
    "allowedDays": ["Saturday", "Sunday"]
  }
}
```

### 6. Health Check Failures

#### Problem
`Post-patch health checks fail`

#### Symptoms
- Nodes marked as unhealthy after patching
- Services not responding correctly
- Cluster stability issues

#### Solutions
```bash
# Check node readiness
kubectl get nodes -o wide

# Verify system services
sudo systemctl status kubelet docker

# Check pod status across cluster
kubectl get pods --all-namespaces -o wide

# Validate network connectivity
kubectl run test-pod --image=busybox --rm -it --restart=Never -- nslookup kubernetes.default.svc.cluster.local
```

### 7. Rollback Procedures

#### Problem
`Need to rollback failed patching operation`

#### Symptoms
- Cluster instability after patching
- Critical workloads not functioning
- Performance degradation

#### Solutions
```bash
# Emergency rollback procedure
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:region:account:stateMachine:eks-rollback-orchestrator \
  --input '{"clusterName":"your-cluster","rollbackPoint":"pre-patch-snapshot"}'

# Manual node replacement
kubectl cordon node-name
kubectl drain node-name --ignore-daemonsets --delete-emptydir-data
# Replace node through ASG or node group refresh
```

## Monitoring and Debugging

### CloudWatch Logs
```bash
# View patching logs
aws logs filter-log-events --log-group-name /aws/lambda/eks-patching-coordinator --start-time 1640995200000

# Monitor Step Functions execution
aws logs filter-log-events --log-group-name /aws/stepfunctions/EKSPatchingOrchestrator
```

### Metrics and Alarms
```bash
# Check patching success rate
aws cloudwatch get-metric-statistics \
  --namespace "EKS/Patching" \
  --metric-name "SuccessRate" \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### Debug Mode
```json
{
  "debugMode": true,
  "verboseLogging": true,
  "dryRun": true,
  "skipHealthChecks": false
}
```

## Performance Optimization

### Batch Size Tuning
- Start with small batch sizes (1-2 nodes)
- Gradually increase based on cluster capacity
- Consider pod disruption budgets

### Parallel Processing
- Enable parallel processing for large clusters
- Monitor resource utilization
- Adjust concurrency limits

### Timeout Configuration
```json
{
  "timeouts": {
    "nodePatching": 1800,
    "healthCheck": 300,
    "drainTimeout": 600,
    "rollbackTimeout": 900
  }
}
```

## Emergency Contacts

### Escalation Procedures
1. **Level 1**: Check automated monitoring and alerts
2. **Level 2**: Review logs and attempt standard remediation
3. **Level 3**: Contact platform engineering team
4. **Level 4**: Engage vendor support if needed

### Support Resources
- Internal Wiki: `https://wiki.company.com/eks-patching`
- On-call Rotation: `+1-555-EKS-HELP`
- Slack Channel: `#eks-patching-support`
