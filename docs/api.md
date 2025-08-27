# EKS Patching Workflow API Reference

## Overview

This document provides comprehensive API documentation for the EKS Patching Workflow system, including Lambda functions, Step Functions, and SSM automation documents.

## Step Functions State Machines

### EKS Patching Orchestrator

**State Machine ARN Pattern:** `arn:aws:states:region:account:stateMachine:eks-patching-orchestrator`

#### Input Schema
```json
{
  "clusterName": "string",
  "patchingStrategy": "rolling|blue-green",
  "maintenanceWindow": "string",
  "dryRun": boolean,
  "nodeGroupFilters": ["string"]
}
```

#### Output Schema
```json
{
  "executionId": "string",
  "status": "SUCCEEDED|FAILED|TIMED_OUT",
  "patchedNodes": number,
  "errors": ["string"],
  "duration": "string"
}
```

## Lambda Functions

### eks-patching-coordinator

**Function Name:** `eks-patching-coordinator`

#### Request Format
```json
{
  "action": "start|stop|status",
  "clusterArn": "string",
  "parameters": {
    "strategy": "rolling",
    "batchSize": 1,
    "maxUnavailable": "25%"
  }
}
```

#### Response Format
```json
{
  "statusCode": 200,
  "body": {
    "taskId": "string",
    "status": "RUNNING|COMPLETED|FAILED",
    "message": "string"
  }
}
```

### eks-node-health-checker

**Function Name:** `eks-node-health-checker`

#### Request Format
```json
{
  "clusterName": "string",
  "nodeGroupName": "string",
  "healthChecks": ["kubelet", "docker", "networking"]
}
```

#### Response Format
```json
{
  "statusCode": 200,
  "body": {
    "healthyNodes": ["string"],
    "unhealthyNodes": ["string"],
    "healthSummary": {
      "total": number,
      "healthy": number,
      "unhealthy": number
    }
  }
}
```

## SSM Automation Documents

### EKS-PatchNode

**Document Name:** `EKS-PatchNode`

#### Parameters
- `InstanceId` (String): EC2 instance ID to patch
- `RebootOption` (String): NoReboot|RebootIfNeeded
- `IncludeKb` (StringList): Specific KB articles to include
- `ExcludeKb` (StringList): Specific KB articles to exclude

#### Automation Steps
1. Pre-patch health check
2. Drain Kubernetes node
3. Apply system patches
4. Reboot if required
5. Post-patch validation
6. Re-join node to cluster

## CloudWatch Events

### Patching Status Events

**Event Source:** `eks.patching.workflow`

#### Event Types
- `patching.started`
- `patching.node.completed`
- `patching.completed`
- `patching.failed`

#### Event Schema
```json
{
  "source": "eks.patching.workflow",
  "detail-type": "EKS Patching Status",
  "detail": {
    "clusterName": "string",
    "nodeGroupName": "string",
    "status": "string",
    "timestamp": "string",
    "metadata": {}
  }
}
```

## Error Codes

| Code | Description | Action |
|------|-------------|--------|
| EKS001 | Cluster not found | Verify cluster name and region |
| EKS002 | Node group not accessible | Check IAM permissions |
| EKS003 | Patching timeout | Increase timeout parameters |
| EKS004 | Health check failed | Review node status |
| EKS005 | Rollback required | Automatic rollback initiated |

## Rate Limits

- Step Functions executions: 2000 per second
- Lambda concurrent executions: 1000 per region
- SSM command executions: 100 per second per account

## Best Practices

1. **Batch Processing**: Process nodes in small batches to maintain cluster availability
2. **Health Checks**: Always verify node health before and after patching
3. **Monitoring**: Use CloudWatch metrics for real-time status tracking
4. **Error Handling**: Implement comprehensive error handling and retry logic
5. **Testing**: Validate in non-production environments first
