<div align="center">
  <img src="https://img.shields.io/badge/%F0%9F%9A%80-EKS%20Upgrade%20Platform-blue?style=for-the-badge&logoColor=white" alt="EKS Upgrades"/>
  <img src="https://img.shields.io/badge/%F0%9F%8F%A2-Multi%20Account-orange?style=for-the-badge" alt="Multi Account"/>
  <img src="https://img.shields.io/badge/%E2%9A%A1-Production%20Grade-green?style=for-the-badge" alt="Production Grade"/>
</div>

<div align="center">
  <h1>🚀 Enterprise EKS Multi-Account Upgrade Platform</h1>
  <p><strong>Enterprise-grade EKS upgrade orchestration for 1000+ AWS accounts</strong></p>
</div>

<div align="center">

[![Terraform](https://img.shields.io/badge/Terraform-1.5%2B-623CE4?style=for-the-badge&logo=terraform&logoColor=white)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-EKS-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/eks/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.24%2B-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

## 🏆 Production-Grade EKS Upgrade Orchestration

This platform deploys an **enterprise-grade** EKS upgrade orchestrator using hub-and-spoke architecture for **1000+ AWS accounts** with automated upgrade workflows, Karpenter integration, manual approval gates, intelligent Bedrock analysis, and comprehensive monitoring.

## 📋 Table of Contents

- [🏗️ Architecture Overview](#️-architecture-overview)
- [Variables (hub)](#variables-hub)
- [Variables (spoke)](#variables-spoke)
- [Deploy – Hub](#deploy--hub)
- [Deploy – Spoke](#deploy--spoke)
- [Manual Approval](#manual-approval)
- [CloudWatch Dashboard](#cloudwatch-dashboard)

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        HUB ACCOUNT                              │
│                (EKS Upgrade Control Plane)                     │
│  ┌─────────────────┐  ┌───────────────────┐  ┌───────────────┐ │
│  │   EventBridge   │  │ Step Functions    │  │   Lambda      │ │
│  │   (Scheduler)   │◄─┤   Orchestrator    │◄─┤   Processors  │ │
│  │                 │  │                   │  │               │ │
│  └─────────────────┘  └───────────────────┘  └───────────────┘ │
│           │                      │                      │       │
│           │             ┌────────▼────────┐            │       │
│           │             │   Bedrock AI    │            │       │
│           │             │   Analysis      │            │       │
│           │             └─────────────────┘            │       │
│           │                                            │       │
│  ┌────────▼────────┐  ┌─────────────────┐  ┌──────────▼──────┐ │
│  │   CloudWatch    │  │     SNS/SQS     │  │   DynamoDB      │ │
│  │   Dashboard     │  │   Notifications │  │   State Store   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ Cross-Account AssumeRole
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────▼─────────┐    ┌────────▼────────┐    ┌────────▼────────┐
│  SPOKE ACCOUNT 1  │    │  SPOKE ACCOUNT 2 │    │ SPOKE ACCOUNT N │
│                   │    │                  │    │                 │
│ ┌───────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │  Cross-Account│ │    │ │Cross-Account │ │    │ │Cross-Account│ │
│ │  Exec Role    │ │    │ │ Exec Role    │ │    │ │ Exec Role   │ │
│ └───────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│ ┌───────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │  EKS Cluster  │ │    │ │ EKS Cluster  │ │    │ │ EKS Cluster │ │
│ │  + Karpenter  │ │    │ │ + Karpenter  │ │    │ │ + Karpenter │ │
│ │  + Add-ons    │ │    │ │ + Add-ons    │ │    │ │ + Add-ons   │ │
│ └───────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└───────────────────┘    └──────────────────┘    └─────────────────┘
```

### Key Components

- **🎯 Hub Account**: Centralized EKS upgrade orchestration
- **🔄 Spoke Accounts**: Target accounts with EKS clusters
- **📅 Wave Management**: Cluster grouping with maintenance windows
- **🤖 AI Analysis**: Bedrock-powered upgrade impact assessment
- **✅ Approval Gates**: Manual approval workflow with notifications
- **🔄 Karpenter**: Automated node refresh and scaling
- **📊 Monitoring**: Real-time dashboards and alerting

## Variables (hub)
- `region` – e.g. `us-east-1`
- `orchestrator_account_id` – 12-digit account ID of hub
- `name_prefix` – e.g. `eksupgrade`
- `sns_email_subscriptions` – emails to notify (optional)
- `wave_rules` – list of objects `{ name, schedule_expression, accounts, regions }` (per-account waves)
- `bedrock_agent_id`, `bedrock_agent_alias_id`
- `wave_pause_seconds`, `abort_on_issues`

## Variables (spoke)
- `region`
- `orchestrator_account_id`
- `role_name` (default `PatchExecRole`)

## Deploy – Hub
```
cd terraform/hub
terraform init
terraform apply   -var='region=us-east-1'   -var='orchestrator_account_id=111111111111'   -var='name_prefix=eksupgrade'   -var='bedrock_agent_id=AGENT_ID'   -var='bedrock_agent_alias_id=ALIAS_ID'   -var='wave_rules=[
      { name="use1-wave1", schedule_expression="cron(0 3 ? * SUN *)", accounts=["222222222222"], regions=["us-east-1"] }
    ]'
```
> **Customize EventBridge input in `aws_cloudwatch_event_target.waves.input`** to set each cluster’s `clusterName`, `targetVersion`, `roleArn`, and `controllerInstanceId` (per wave).

## Deploy – Spoke
```
cd terraform/spoke
terraform init
terraform apply -var='region=us-east-1' -var='orchestrator_account_id=111111111111'
```

## Manual Approval
Identical to EC2: email links `Approve/Reject` continue or fail the state machine before upgrades.

## CloudWatch Dashboard
A dashboard `${name_prefix}-dashboard` with Step Functions and Lambda error metrics.
