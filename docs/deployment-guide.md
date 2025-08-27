# EKS Patching Workflow Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the EKS Patching Workflow across hub and spoke architectures.

## Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- kubectl configured
- Docker installed for container builds

## Architecture Components

### Hub Account Deployment
- Central orchestration workflows
- Cross-account IAM roles
- CloudWatch monitoring
- SSM Parameter Store configuration

### Spoke Account Deployment
- Target EKS clusters
- Local IAM roles and policies
- Patching agents
- Status reporting mechanisms

## Deployment Steps

### 1. Hub Account Setup

```bash
cd terraform/hub
terraform init
terraform plan -var-file="../../examples/hub.auto.tfvars.example"
terraform apply
```

### 2. Spoke Account Setup

```bash
cd terraform/spoke
terraform init
terraform plan -var-file="../../examples/spoke.auto.tfvars.example"
terraform apply
```

### 3. Verification

```bash
# Verify hub deployment
aws stepfunctions list-state-machines --region us-east-1

# Verify spoke connectivity
kubectl get nodes -o wide
aws ssm describe-instance-information
```

## Configuration

See [Configuration Guide](../README.md#configuration) for detailed parameter explanations.

## Troubleshooting

See [Troubleshooting Guide](./troubleshooting-guide.md) for common issues and solutions.
