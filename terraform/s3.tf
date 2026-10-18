# s3.tf — the three study buckets.
#
#   ${prefix}-code  : versioned store for the AgentCore agent ZIP (direct code deployment).
#   ${prefix}-data  : experiment fixtures (incident docs, carriers, canaries, seeded by seed_fixtures.py).
#   ${prefix}-trail : CloudTrail log delivery.
#
# All buckets use SSE-S3 (AES256), block all public access, and are NOT force
# destroyed: terraform destroy will refuse to delete a non-empty bucket, which
# is deliberate (manual section 13 archives evidence before teardown).

resource "aws_s3_bucket" "code" {
  bucket        = "${local.prefix}-code"
  force_destroy = true
}

resource "aws_s3_bucket" "data" {
  bucket        = "${local.prefix}-data"
  force_destroy = true
}

resource "aws_s3_bucket" "trail" {
  bucket        = "${local.prefix}-trail"
  force_destroy = true
}

# Only the code bucket is versioned: agent.zip revisions are the deployment
# history the study freezes against (manual section 9, freeze.py).
resource "aws_s3_bucket_versioning" "code" {
  bucket = aws_s3_bucket.code.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "code" {
  bucket = aws_s3_bucket.code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "code" {
  bucket                  = aws_s3_bucket.code.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy for CloudTrail delivery, written per the AWS CloudTrail
# documentation "Creating an Amazon S3 bucket policy for CloudTrail"
# (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html):
# cloudtrail.amazonaws.com may check the bucket ACL, list the bucket, and
# write log objects with bucket-owner-full-control, restricted to this
# account's trail via the AWS:SourceArn condition.
resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailListBucket"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.prefix}-trail"
          }
        }
      },
    ]
  })
}
