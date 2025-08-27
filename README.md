# EKS Upgrade & Karpenter – Terraform (Hub & Spoke)

This codebase deploys a **production-grade** EKS upgrade orchestrator with **per-account wave windows**, **manual approval**, **SNS alerts**, **Bedrock analysis**, and a **CloudWatch dashboard**. It also provides the **cross-account role** for clusters in spoke accounts.

## Structure
```
terraform/
  hub/    # deploy in HUB (orchestrator) account
  spoke/  # deploy in each TARGET (spoke) account
.github/workflows/
examples/
```

## Prereqs
- Terraform >= 1.5, AWS CLI, and an **OIDC-enabled GitHub role** in each account (or local credentials).
- EKS clusters already exist and are healthy.
- A controller instance or mechanism with `kubectl` for Karpenter (see `controllerInstanceId`).

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
