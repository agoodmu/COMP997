# main.tf — provider, identity, and study naming.

terraform {
  required_version = ">= 1.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.33"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  # prefix is used for ordinary AWS resource names (S3, DynamoDB, SNS, ...).
  prefix = "comp997-${var.suffix}"

  # name is used for the AgentCore runtime, whose agent_runtime_name must match
  # [a-zA-Z][a-zA-Z0-9_]{0,47}: underscores instead of hyphens.
  name = "comp997_${var.suffix}"

  account_id = data.aws_caller_identity.current.account_id
}
