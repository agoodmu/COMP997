# logs.tf — the AgentCore runtime's CloudWatch log group.
#
# ASSUMPTION: the runtime writes to a log group named
# /aws/bedrock-agentcore/runtimes/<runtime ID>. This matches the AgentCore
# observability documentation, but you MUST verify it against the real log
# stream names in the section 8 pilot step (aws logs filter-log-events with
# the agentcore_log_group output). If the runtime uses a different group name,
# update this resource to match instead of creating a second, unused group.
#
# Manual section 14: if terraform apply reports that this log group already
# exists (e.g. a previous partial deployment created it), import it instead of
# deleting it:
#   terraform -chdir=terraform import aws_cloudwatch_log_group.agent \
#     "/aws/bedrock-agentcore/runtimes/<agent_runtime_id>"

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/aws/bedrock-agentcore/runtimes/${aws_bedrockagentcore_agent_runtime.main.agent_runtime_id}"
  retention_in_days = var.log_retention_days

  tags = {
    Study = local.prefix
  }
}

# --- CloudTrail -> CloudWatch Logs (kit v3) --------------------------------
# The trail delivers every event to this log group so the evidence script can
# query CloudTrail the same way it queries the Lambda and runtime logs
# (Logs Insights). CloudTrail creates one log stream per region/account.
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.prefix}"
  retention_in_days = var.log_retention_days

  tags = {
    Study = local.prefix
  }
}
