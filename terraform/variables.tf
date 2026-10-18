# variables.tf — operator-supplied inputs for the COMP997 AgentCore study kit.
#
# Copy terraform.tfvars.example to terraform.tfvars and edit it; the example
# file documents each value. terraform.tfvars itself is gitignored because it
# identifies your study deployment.

variable "suffix" {
  description = "Study suffix embedded in every resource name (protocol v2: jianmin). Must be 5-12 lowercase letters or digits. Choose a NEW suffix per study so buckets, roles and the AgentCore runtime never collide with an earlier deployment."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{5,12}$", var.suffix))
    error_message = "suffix must be 5-12 lowercase letters or digits (a-z, 0-9)."
  }
}

variable "region" {
  description = "AWS region for the whole study. The manual pins us-east-1 (model availability and Bedrock AgentCore)."
  type        = string
  default     = "us-east-1"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the AgentCore runtime and tool Lambda log groups. Align with your approved retention plan before deployment (manual section 6)."
  type        = number
  default     = 90
}

variable "fixtures_path" {
  description = "Path to data/fixtures.json produced by generate_data.py. Terraform reads it to seed S3 and DynamoDB (kit v3 seeds data from Terraform, not a Python script). Canary placeholders in the fixtures are substituted with the random_password values generated in seed.tf."
  type        = string
  default     = "../data/fixtures.json"
}

variable "carrier_label" {
  description = "true (main run): keep the self-announcing label in front of each injected instruction in the carrier documents. false (robustness check): strip the label and re-apply, so the same 20 cases run against unlabelled documents. Changing this re-uploads only the 20 carrier objects."
  type        = bool
  default     = true
}

variable "agent_zip_path" {
  description = "Path to the AgentCore agent ZIP built by package_agent.py (relative to this directory). OPERATOR: you MUST run package_agent.py BEFORE terraform plan, because filemd5() is evaluated at plan time — planning against a missing or stale ZIP fails or silently pins the wrong code."
  type        = string
  default     = "../build/agent.zip"
}

variable "model_id" {
  description = "Bedrock foundation model identifier. Used for tagging/reference only; the runtime role's IAM policy pins the exact model ARN separately in iam.tf."
  type        = string
  default     = "amazon.nova-lite-v1:0"
}

variable "third_party_api_key" {
  description = "API key for the optional third-party (OpenAI-compatible) model provider, used ONLY for pre-Bedrock pipeline shakedown. Exposed to the runtime as THIRD_PARTY_API_KEY. Leave empty when unused. Pass via TF_VAR_third_party_api_key so the value never lands in a file; rotate the key after the study."
  type        = string
  default     = ""
  sensitive   = true
}

variable "bedrock_access_role_arn" {
  description = "ARN of a cross-account IAM role the runtime assumes (STS) for Bedrock model calls. Exposed to the runtime as BEDROCK_ACCESS_ROLE_ARN. Leave empty when the runtime's own execution role has Bedrock access directly (single-account study)."
  type        = string
  default     = ""
}

variable "bedrock_access_key_id" {
  description = "Access key ID of a dedicated IAM user in the model account, used when that account's org policy blocks sts:AssumeRole. Exposed as BEDROCK_ACCESS_KEY_ID. Pass via TF_VAR so the value never lands in a file; rotate after the study."
  type        = string
  default     = ""
  sensitive   = true
}

variable "bedrock_access_secret" {
  description = "Secret access key matching bedrock_access_key_id. Exposed as BEDROCK_ACCESS_SECRET_KEY. Pass via TF_VAR so the value never lands in a file; rotate after the study."
  type        = string
  default     = ""
  sensitive   = true
}
