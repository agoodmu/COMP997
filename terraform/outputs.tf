# outputs.tf — everything the kit's Python scripts read from
# private/terraform_outputs.json (written by `terraform output -json` in
# manual section 6). Do not remove an output without updating the scripts
# that consume it.

# --- AgentCore runtime ---
output "agent_runtime_id" {
  description = "AgentCore runtime ID (used by get-agent-runtime / invoke-agent-runtime)."
  value       = aws_bedrockagentcore_agent_runtime.main.agent_runtime_id
}

output "agent_runtime_arn" {
  description = "AgentCore runtime ARN (used by invoke permissions and evidence joins)."
  value       = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
}

output "agentcore_log_group" {
  description = "CloudWatch log group holding the runtime's session logs (manual section 8)."
  value       = aws_cloudwatch_log_group.agent.name
}

# --- CloudTrail ---
output "trail_name" {
  description = "Trail name (used by get-trail-status / get-event-selectors)."
  value       = aws_cloudtrail.trail.name
}

output "trail_arn" {
  description = "Trail ARN (used by validate-logs in manual section 10)."
  value       = aws_cloudtrail.trail.arn
}

# --- Buckets ---
output "code_bucket" {
  description = "Versioned bucket holding agent/agent.zip."
  value       = aws_s3_bucket.code.id
}

output "data_bucket" {
  description = "Bucket holding seeded fixtures (documents, carriers, canaries)."
  value       = aws_s3_bucket.data.id
}

output "trail_bucket" {
  description = "Bucket receiving CloudTrail log delivery."
  value       = aws_s3_bucket.trail.id
}

# --- DynamoDB ---
output "table_name" {
  description = "Synthetic customer-record table name."
  value       = aws_dynamodb_table.records.name
}

output "table_arn" {
  description = "Synthetic customer-record table ARN."
  value       = aws_dynamodb_table.records.arn
}

output "protected_table_name" {
  description = "Protected-record table name (holds only pk CUST#protected)."
  value       = aws_dynamodb_table.protected_records.name
}

# --- SNS/SQS ---
output "topic_arn" {
  description = "Study notification topic ARN (send_notification target)."
  value       = aws_sns_topic.notifications.arn
}

output "queue_url" {
  description = "Notification sink queue URL (evidence export before 1-day retention expires)."
  value       = aws_sqs_queue.sink.id
}

output "queue_arn" {
  description = "Notification sink queue ARN."
  value       = aws_sqs_queue.sink.arn
}

# --- Tool Lambda functions ---
output "lambda_broad" {
  description = "Broad baseline tool function name (C0/C1/C3 dispatch target)."
  value       = aws_lambda_function.tool_broad.function_name
}

output "lambda_broad_arn" {
  description = "Broad baseline tool function ARN."
  value       = aws_lambda_function.tool_broad.arn
}

output "lambda_read_document" {
  description = "Restricted read_document function name (C2/C4 dispatch target)."
  value       = aws_lambda_function.tool_read_document.function_name
}

output "lambda_read_document_arn" {
  description = "Restricted read_document function ARN."
  value       = aws_lambda_function.tool_read_document.arn
}

output "lambda_get_record" {
  description = "Restricted get_record function name (C2/C4 dispatch target)."
  value       = aws_lambda_function.tool_get_record.function_name
}

output "lambda_get_record_arn" {
  description = "Restricted get_record function ARN."
  value       = aws_lambda_function.tool_get_record.arn
}

output "lambda_send_notification" {
  description = "Restricted send_notification function name (C2/C4 dispatch target)."
  value       = aws_lambda_function.tool_send_notification.function_name
}

output "lambda_send_notification_arn" {
  description = "Restricted send_notification function ARN."
  value       = aws_lambda_function.tool_send_notification.arn
}

# --- Identity / study parameters ---
output "runtime_role_arn" {
  description = "AgentCore runtime execution role ARN."
  value       = aws_iam_role.runtime.arn
}

output "region" {
  description = "Study AWS region."
  value       = var.region
}

output "suffix" {
  description = "Study suffix used in resource names."
  value       = var.suffix
}

# --- Log groups for the evidence script (kit v3) ---
output "trail_log_group" {
  description = "CloudWatch log group that receives CloudTrail events (evidence/collect_evidence.sh queries this for RQ3)."
  value       = aws_cloudwatch_log_group.trail.name
}

output "lambda_log_groups" {
  description = "The four tool-Lambda CloudWatch log groups."
  value = [
    aws_cloudwatch_log_group.tool_broad.name,
    aws_cloudwatch_log_group.tool_read_document.name,
    aws_cloudwatch_log_group.tool_get_record.name,
    aws_cloudwatch_log_group.tool_send_notification.name,
  ]
}

output "carrier_label" {
  description = "Whether the carrier documents currently carry the self-announcing label (true = main run, false = robustness check)."
  value       = var.carrier_label
}
