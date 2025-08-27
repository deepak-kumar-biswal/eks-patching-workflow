variable "region" { type = string }
variable "orchestrator_account_id" {
  type        = string
  description = "12-digit AWS account ID for the hub/orchestrator"
}

# EC2-only: used for SNS topic name, S3 bucket names, etc
variable "name_prefix" {
  type        = string
  description = "Short name to prefix resources (e.g., ec2patch or eksupgrade)"
}

variable "sns_email_subscriptions" {
  type        = list(string)
  default     = []
  description = "Optional list of email addresses to subscribe to SNS notifications"
}

# Wave rules: provide a list of objects for scheduling per-account waves
# Each object includes: name, schedule_expression (cron), accounts, regions
variable "wave_rules" {
  description = "Per-account wave schedules for EventBridge rules"
  type = list(object({
    name                = string
    schedule_expression = string
    accounts            = list(string)
    regions             = list(string)
  }))
  default = []
}

# Bedrock agent configuration
variable "bedrock_agent_id" { type = string }
variable "bedrock_agent_alias_id" { type = string }

# Optional pause seconds between waves when invoked via SFN directly
variable "wave_pause_seconds" {
  type    = number
  default = 0
}

variable "abort_on_issues" {
  type    = bool
  default = true
}
