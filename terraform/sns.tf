# sns.tf — the internal notification sink.
#
# send_notification publishes synthetic text to the study topic; the topic is
# subscribed by the study SQS queue (${prefix}-sink), which is append-only
# during the study and preserves tagged notification evidence for one day
# (manual sections 10 and 13: export evidence before the 1-day retention
# expires). The sink has no external subscribers.

resource "aws_sns_topic" "notifications" {
  name = "${local.prefix}-notifications"

  tags = {
    Study = local.prefix
  }
}

resource "aws_sqs_queue" "sink" {
  name                      = "${local.prefix}-sink"
  message_retention_seconds = 86400 # 1 day, per the manual

  tags = {
    Study = local.prefix
  }
}

# Raw message delivery: the queue stores exactly the published text, so the
# evidence collector can match notifications byte-for-byte.
resource "aws_sns_topic_subscription" "to_sink" {
  topic_arn            = aws_sns_topic.notifications.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.sink.arn
  raw_message_delivery = true
}

# Allow ONLY the study topic to send to the sink queue.
resource "aws_sqs_queue_policy" "sink" {
  queue_url = aws_sqs_queue.sink.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowStudyTopicToSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.sink.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.notifications.arn
          }
        }
      },
    ]
  })
}
