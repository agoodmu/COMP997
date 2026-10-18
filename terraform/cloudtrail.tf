# cloudtrail.tf — the study trail (RQ3 native evidence).
#
# The trail records management events plus data events on every study
# resource: the data bucket objects, the DynamoDB table, the SNS topic, the
# four tool Lambdas, and the AgentCore runtime + its DEFAULT endpoint.
# Log file validation is enabled (digest files); manual section 10 verifies
# digests explicitly rather than assuming validation happened.
#
# OPERATOR, READ THIS: after apply you MUST verify the selectors with
#   aws cloudtrail get-event-selectors --trail-name <trail_name> --region us-east-1
# (manual section 6). The CloudTrail console event history and lookup-events
# do NOT replace delivery of these selected data events to the trail bucket.
# In particular, confirm that your account/region supports data-event logging
# for AWS::BedrockAgentCore::Runtime and AWS::BedrockAgentCore::RuntimeEndpoint;
# if a type is rejected at apply time, record the deviation in the study
# notebook instead of silently dropping coverage.
#
# NOTE: the logging switch is `enable_logging` in this provider version
# (verified against the installed provider schema).

resource "aws_cloudtrail" "trail" {
  name                       = "${local.prefix}-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  enable_log_file_validation = true
  enable_logging             = true

  # kit v3: the trail ALSO delivers every event to CloudWatch Logs, so all
  # evidence (CloudTrail, the tool Lambdas, the runtime) is queried the same
  # way, with `aws logs start-query` (see evidence/collect_evidence.sh). The
  # S3 copy is kept for log-file validation (digests).
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cwl.arn

  # NOTE: this provider forbids mixing event_selector with
  # advanced_event_selector on one trail, so management events are expressed
  # as an advanced selector too (equivalent to read_write_type="All" with
  # global service events included).
  # CloudTrail further limits resources.type to ONE value per advanced
  # selector (verified 2026-10-04: apply rejects multiple values), so each
  # data-event type gets its own selector, scoped to study ARNs.
  # SNS Publish is a MANAGEMENT event in CloudTrail (no SNS data-event type
  # exists), so it is captured by the management selector below; no data
  # selector is needed for the topic.
  advanced_event_selector {
    name = "study-management-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "study-s3-data"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.data.arn}/"]
    }
  }

  # kit v3 logs EVERYTHING: the DynamoDB data selector covers BOTH the main
  # table and the protected table (kit v2 omitted the protected table, which
  # was the central RQ3 finding; v3 closes that gap on purpose).
  advanced_event_selector {
    name = "study-ddb-data"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::DynamoDB::Table"]
    }

    field_selector {
      field = "resources.ARN"
      equals = [
        aws_dynamodb_table.records.arn,
        aws_dynamodb_table.protected_records.arn,
      ]
    }
  }

  advanced_event_selector {
    name = "study-lambda-data"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = [
        aws_lambda_function.tool_broad.arn,
        aws_lambda_function.tool_read_document.arn,
        aws_lambda_function.tool_get_record.arn,
        aws_lambda_function.tool_send_notification.arn,
      ]
    }
  }

  # kit v3 logs EVERYTHING: SNS Publish is a DATA event (not management), so
  # it needs its own selector. CloudTrail records that a Publish happened to
  # the topic, but NOT the message body — the message text (which can carry an
  # exfiltrated record or canary) is never in CloudTrail. That gap is a
  # deliberate RQ3 finding, now demonstrable rather than assumed.
  advanced_event_selector {
    name = "study-sns-data"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::SNS::Topic"]
    }

    field_selector {
      field  = "resources.ARN"
      equals = [aws_sns_topic.notifications.arn]
    }
  }

  # BedrockAgentCore data-event coverage for InvokeAgentRuntime. If apply
  # rejects this type, remove this selector and record the deviation in the
  # study notebook (manual section 6) — session linkage then rests on the
  # runtime's CloudWatch logs plus the runner's session records.
  advanced_event_selector {
    name = "study-agentcore-data"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::BedrockAgentCore::Runtime"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = [aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}
