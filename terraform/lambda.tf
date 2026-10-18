# lambda.tf — the four tool functions.
#
# One handler source (lambda_src/handler.py), deployed four times with a
# different TOOL_MODE environment variable:
#   ${prefix}-tool-broad             TOOL_MODE=broad             (C0/C1/C3 baseline path)
#   ${prefix}-tool-read-document     TOOL_MODE=read_document     (C2/C4 restricted)
#   ${prefix}-tool-get-record        TOOL_MODE=get_record        (C2/C4 restricted)
#   ${prefix}-tool-send-notification TOOL_MODE=send_notification (C2/C4 restricted)
#
# The handler has no third-party dependencies (boto3/botocore ship in the
# Lambda Python runtime), so the bundle is zipped straight from lambda_src/.
# The zip is written to ../build/ (gitignored) at plan time by the
# archive_file data source.

data "archive_file" "tool_bundle" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/../build/tool_functions.zip"
}

# --- CloudWatch log groups (one per function, pre-created so the study's
# --- retention is applied from the first invocation) ---

resource "aws_cloudwatch_log_group" "tool_broad" {
  name              = "/aws/lambda/${local.prefix}-tool-broad"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "tool_read_document" {
  name              = "/aws/lambda/${local.prefix}-tool-read-document"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "tool_get_record" {
  name              = "/aws/lambda/${local.prefix}-tool-get-record"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "tool_send_notification" {
  name              = "/aws/lambda/${local.prefix}-tool-send-notification"
  retention_in_days = var.log_retention_days
}

# --- Functions ---

resource "aws_lambda_function" "tool_broad" {
  function_name    = "${local.prefix}-tool-broad"
  role             = aws_iam_role.lambda_broad.arn
  filename         = data.archive_file.tool_bundle.output_path
  source_code_hash = data.archive_file.tool_bundle.output_base64sha256
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  timeout          = 30

  environment {
    variables = {
      TOOL_MODE   = "broad"
      DATA_BUCKET = aws_s3_bucket.data.id
      TABLE_NAME         = aws_dynamodb_table.records.name
      PROTECTED_TABLE_NAME = aws_dynamodb_table.protected_records.name
      TOPIC_ARN          = aws_sns_topic.notifications.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.tool_broad]
}

resource "aws_lambda_function" "tool_read_document" {
  function_name    = "${local.prefix}-tool-read-document"
  role             = aws_iam_role.lambda_read_document.arn
  filename         = data.archive_file.tool_bundle.output_path
  source_code_hash = data.archive_file.tool_bundle.output_base64sha256
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  timeout          = 30

  environment {
    variables = {
      TOOL_MODE   = "read_document"
      DATA_BUCKET = aws_s3_bucket.data.id
      TABLE_NAME         = aws_dynamodb_table.records.name
      PROTECTED_TABLE_NAME = aws_dynamodb_table.protected_records.name
      TOPIC_ARN          = aws_sns_topic.notifications.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.tool_read_document]
}

resource "aws_lambda_function" "tool_get_record" {
  function_name    = "${local.prefix}-tool-get-record"
  role             = aws_iam_role.lambda_get_record.arn
  filename         = data.archive_file.tool_bundle.output_path
  source_code_hash = data.archive_file.tool_bundle.output_base64sha256
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  timeout          = 30

  environment {
    variables = {
      TOOL_MODE   = "get_record"
      DATA_BUCKET = aws_s3_bucket.data.id
      TABLE_NAME         = aws_dynamodb_table.records.name
      PROTECTED_TABLE_NAME = aws_dynamodb_table.protected_records.name
      TOPIC_ARN          = aws_sns_topic.notifications.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.tool_get_record]
}

resource "aws_lambda_function" "tool_send_notification" {
  function_name    = "${local.prefix}-tool-send-notification"
  role             = aws_iam_role.lambda_send_notification.arn
  filename         = data.archive_file.tool_bundle.output_path
  source_code_hash = data.archive_file.tool_bundle.output_base64sha256
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  timeout          = 30

  environment {
    variables = {
      TOOL_MODE   = "send_notification"
      DATA_BUCKET = aws_s3_bucket.data.id
      TABLE_NAME         = aws_dynamodb_table.records.name
      PROTECTED_TABLE_NAME = aws_dynamodb_table.protected_records.name
      TOPIC_ARN          = aws_sns_topic.notifications.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.tool_send_notification]
}
