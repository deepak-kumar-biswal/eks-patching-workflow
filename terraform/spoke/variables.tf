variable "region" { type = string }

variable "orchestrator_account_id" {
  type        = string
  description = "12-digit AWS account ID for the hub/orchestrator (trusted principal)"
}

variable "role_name" {
  type        = string
  default     = "PatchExecRole"
  description = "Name of the cross-account role to create in the spoke account"
}
