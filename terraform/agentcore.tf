# agentcore.tf — the AgentCore Runtime, deployed by DIRECT CODE DEPLOYMENT.
#
# No Docker, ECR, CDK, or AgentCore deployment CLI: the operator builds
# build/agent.zip with package_agent.py (manual section 5), Terraform uploads
# it to the versioned code bucket, and the runtime pulls it from S3.
# The agent serves POST /invocations and GET /ping on port 8080 from
# runtime_main.py (built by the teammate's packaging step).

# Upload the agent ZIP to the code bucket. source_hash pins the exact bytes
# deployed; any rebuild changes the hash and forces a replacement object.
# NOTE: var.agent_zip_path and filemd5() are evaluated at PLAN time, so the
# operator must have run package_agent.py before terraform plan (see
# variables.tf).
resource "aws_s3_object" "agent_zip" {
  bucket      = aws_s3_bucket.code.id
  key         = "agent/agent.zip"
  source      = var.agent_zip_path
  source_hash = filemd5(var.agent_zip_path)
}

# NOTE on the block shape below: code_configuration { code { s3 { bucket,
# prefix } } runtime entry_point } — verified against the hashicorp/aws
# provider schema (terraform providers schema). The s3 block must be nested
# inside a code block; a bare s3 block under code_configuration is rejected
# by terraform validate.
resource "aws_bedrockagentcore_agent_runtime" "main" {
  agent_runtime_name = local.name # underscores: matches [a-zA-Z][a-zA-Z0-9_]{0,47}
  role_arn           = aws_iam_role.runtime.arn

  network_configuration {
    network_mode = "PUBLIC"
  }

  agent_runtime_artifact {
    code_configuration {
      code {
        s3 {
          bucket = aws_s3_bucket.code.id
          prefix = "agent/agent.zip"
        }
      }
      runtime     = "PYTHON_3_12"
      entry_point = ["runtime_main.py"]
    }
  }

  environment_variables = {
    AWS_REGION               = var.region
    STUDY_PREFIX             = local.prefix
    THIRD_PARTY_API_KEY      = var.third_party_api_key
    BEDROCK_ACCESS_ROLE_ARN  = var.bedrock_access_role_arn
    BEDROCK_ACCESS_KEY_ID    = var.bedrock_access_key_id
    BEDROCK_ACCESS_SECRET_KEY = var.bedrock_access_secret
    # Code pin: forces a new runtime version whenever the agent ZIP changes.
    # The runtime pulls code from S3 by bucket/prefix (not by object hash),
    # so without this a rebuilt ZIP would upload without cutting a new
    # version, leaving the live endpoint on stale code (seen 2026-10-06).
    AGENT_CODE_SHA256 = filemd5(var.agent_zip_path)
  }

  # The runtime must only be created once the exact ZIP it will run exists in
  # the code bucket.
  depends_on = [aws_s3_object.agent_zip]
}
