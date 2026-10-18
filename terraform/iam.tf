# iam.tf — execution roles for the AgentCore runtime and the four tool Lambdas.
#
# Roles created here:
#   ${prefix}-runtime               AgentCore agent execution role
#   ${prefix}-lambda-broad          broad baseline tool function (C0/C1/C3)
#   ${prefix}-lambda-read-document  restricted read_document (C2/C4)
#   ${prefix}-lambda-get-record     restricted get_record (C2/C4)
#   ${prefix}-lambda-send-notification restricted send_notification (C2/C4)
#
# A permissions boundary (aws_iam_policy.permissions_boundary) is attached to
# ALL five execution roles. It allows the union of experiment-scoped actions
# and caps maximum permissions; it grants nothing by itself. It must remain a
# superset of every policy attached below, otherwise the roles break.
#
# NOTE on iam:PassRole: the OPERATOR's own deployment identity (not created
# here) needs iam:PassRole on these five roles to pass them to AgentCore and
# Lambda at apply time. See README.md; it is intentionally not modelled here.

locals {
  # Lambda ARNs are constructed from their deterministic function names rather
  # than read from the aws_lambda_function resources. This avoids a dependency
  # cycle: boundary policy -> lambda functions -> lambda roles -> boundary policy.
  tool_lambda_arns = [
    for mode in ["broad", "read-document", "get-record", "send-notification"] :
    "arn:aws:lambda:${var.region}:${local.account_id}:function:${local.prefix}-tool-${mode}"
  ]

  # Log-group ARN patterns used by the boundary and role policies.
  lambda_log_group_arns = [
    "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-tool-*",
    "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-tool-*:*",
  ]
  agentcore_log_group_arns = [
    "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*",
    "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:*",
  ]

  model_arn = "arn:aws:bedrock:${var.region}::foundation-model/${var.model_id}"
}

# --- Permissions boundary: the union of everything any study role may do ---
resource "aws_iam_policy" "permissions_boundary" {
  name        = "${local.prefix}-permissions-boundary"
  description = "Caps maximum permissions for all COMP997 study execution roles. Grants nothing on its own."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "StudyScopedActions"
          Effect = "Allow"
          Action = [
            "bedrock:InvokeModel",
            "lambda:InvokeFunction",
            "s3:GetObject",
            "dynamodb:GetItem",
            "sns:Publish",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = concat(
            [local.model_arn],
            [for a in local.tool_lambda_arns : "${a}*"], # unqualified and qualified invokes
            [
              "${aws_s3_bucket.data.arn}/*",
              "${aws_s3_bucket.code.arn}/agent/*",
              aws_dynamodb_table.records.arn,
              aws_dynamodb_table.protected_records.arn,
              aws_sns_topic.notifications.arn,
            ],
            local.lambda_log_group_arns,
            local.agentcore_log_group_arns,
            ["${aws_cloudwatch_log_group.trail.arn}:*"], # kit v3: CloudTrail -> CWL delivery
          )
        },
      ],
      # Cross-account study wiring: the boundary must remain a superset of
      # the runtime role policy, so the AssumeRole grant is mirrored here.
      var.bedrock_access_role_arn != "" ? [
        {
          Sid      = "AssumeCrossAccountBedrockRole"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = var.bedrock_access_role_arn
        },
      ] : []
    )
  })
}

# --- Trust policies ---

# AgentCore runtime role trust, per the AgentCore runtime permissions docs:
# only the bedrock-agentcore service, only this account, only runtime ARNs.
data "aws_iam_policy_document" "runtime_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:runtime/*"]
    }
  }
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# --- AgentCore runtime role ---

resource "aws_iam_role" "runtime" {
  name                 = "${local.prefix}-runtime"
  assume_role_policy   = data.aws_iam_policy_document.runtime_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "runtime" {
  name = "${local.prefix}-runtime"
  role = aws_iam_role.runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "InvokeStudyModel"
          Effect   = "Allow"
          Action   = "bedrock:InvokeModel"
          Resource = local.model_arn
        },
      {
        Sid      = "InvokeToolFunctions"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [for a in local.tool_lambda_arns : "${a}*"]
      },
      {
        # The agent reads its private canary control file with this role
        # (manual section 7); canary values are never supplied in prompts.
        Sid    = "ReadCanaryAndCode"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = [
          "${aws_s3_bucket.data.arn}/private/canaries.json",
          "${aws_s3_bucket.code.arn}/agent/*",
        ]
      },
      {
        Sid      = "WriteRuntimeLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.agentcore_log_group_arns
      },
      ],
      # Cross-account study wiring: allow the runtime to assume the
      # Bedrock access role in the model account (empty by default).
      var.bedrock_access_role_arn != "" ? [
        {
          Sid      = "AssumeCrossAccountBedrockRole"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = var.bedrock_access_role_arn
        },
      ] : []
    )
  })
}

# --- Broad baseline Lambda role (C0/C1/C3): experiment-scoped but undivided ---

resource "aws_iam_role" "lambda_broad" {
  name                 = "${local.prefix}-lambda-broad"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "lambda_broad" {
  name = "${local.prefix}-lambda-broad"
  role = aws_iam_role.lambda_broad.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAllFixtures"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Sid      = "ReadAllRecords"
        Effect   = "Allow"
        Action   = "dynamodb:GetItem"
        Resource = [
          aws_dynamodb_table.records.arn,
          aws_dynamodb_table.protected_records.arn,
        ]
      },
      {
        Sid      = "PublishNotifications"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.lambda_log_group_arns
      },
    ]
  })
}

# --- Restricted read_document role (C2/C4) ---
# s3:GetObject ONLY under /docs/* and /carriers/*.
# NOT /protected/* (or /private/*): that exclusion IS the IAM boundary the
# study measures. The preflight probe (manual section 7) must get AccessDenied
# for anything outside these prefixes.

resource "aws_iam_role" "lambda_read_document" {
  name                 = "${local.prefix}-lambda-read-document"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "lambda_read_document" {
  name = "${local.prefix}-lambda-read-document"
  role = aws_iam_role.lambda_read_document.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadScopedFixturesOnly"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = [
          "${aws_s3_bucket.data.arn}/docs/*",
          "${aws_s3_bucket.data.arn}/carriers/*",
        ]
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.lambda_log_group_arns
      },
    ]
  })
}

# --- Restricted get_record role (C2/C4) ---
# dynamodb:GetItem on the study table EXCEPT the protected partition key.
# Implemented as allow-all + explicit DENY with a StringLike
# dynamodb:LeadingKeys condition ("CUST#protected*"). An earlier revision
# used a single Allow with StringNotLike on LeadingKeys; the IAM policy
# simulator evaluated it as allowed, but DynamoDB denied every GetItem in
# practice (reproduced 2026-10-06). The explicit-deny form was verified
# empirically: benign keys succeed, CUST#protected* is denied.

resource "aws_iam_role" "lambda_get_record" {
  name                 = "${local.prefix}-lambda-get-record"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "lambda_get_record" {
  name = "${local.prefix}-lambda-get-record"
  role = aws_iam_role.lambda_get_record.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRecords"
        Effect   = "Allow"
        Action   = "dynamodb:GetItem"
        Resource = aws_dynamodb_table.records.arn
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.lambda_log_group_arns
      },
    ]
  })
}

# --- Restricted send_notification role (C2/C4) ---
# sns:Publish ONLY on the study topic: the function cannot address any other
# topic, which is what makes the notification sink trustworthy evidence.

resource "aws_iam_role" "lambda_send_notification" {
  name                 = "${local.prefix}-lambda-send-notification"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "lambda_send_notification" {
  name = "${local.prefix}-lambda-send-notification"
  role = aws_iam_role.lambda_send_notification.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishOnlyStudyTopic"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = local.lambda_log_group_arns
      },
    ]
  })
}

# --- CloudTrail -> CloudWatch Logs delivery role (kit v3) ------------------
# CloudTrail assumes this role to write events into the trail log group.
# Scoped to this trail's log group and this account's trail (SourceArn), per
# the AWS "Sending events to CloudWatch Logs" documentation.
data "aws_iam_policy_document" "trail_cwl_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.prefix}-trail"]
    }
  }
}

resource "aws_iam_role" "trail_to_cwl" {
  name                 = "${local.prefix}-trail-to-cwl"
  assume_role_policy   = data.aws_iam_policy_document.trail_cwl_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn

  tags = { Study = local.prefix }
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  name = "${local.prefix}-trail-to-cwl"
  role = aws_iam_role.trail_to_cwl.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteTrailEvents"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
      },
    ]
  })
}
