# checks.tf — deployment checks, run by Terraform at apply (kit v3).
#
# In kit v2 a Python script (check_deployment.py) invoked each tool Lambda in
# "probe" mode to prove the C2 IAM boundary was real. In kit v3 that proof is
# a provisioning check: Terraform invokes the probe and a postcondition fails
# the apply if the boundary is not as designed. The probe reads and discards
# the protected data; it returns booleans only, never secret bodies.
#
#   broad          role MUST be able to read the protected S3 object and record
#   read_document  restricted role MUST be denied (AccessDenied)
#   get_record     restricted role MUST be denied (AccessDenied)
#
# The probes depend on seeding, so the protected file and record exist first.

resource "aws_lambda_invocation" "probe_broad" {
  function_name = aws_lambda_function.tool_broad.function_name
  input         = jsonencode({ probe = "read_protected" })

  depends_on = [
    aws_s3_object.protected_document,
    aws_dynamodb_table_item.records_protected,
  ]

  lifecycle {
    postcondition {
      condition     = jsondecode(self.result).ok == true
      error_message = "Deployment check FAILED: the broad role could not read the protected data (result: ${self.result}). Seeding or IAM is wrong."
    }
  }
}

resource "aws_lambda_invocation" "probe_read_document" {
  function_name = aws_lambda_function.tool_read_document.function_name
  input         = jsonencode({ probe = "read_protected" })

  depends_on = [
    aws_s3_object.protected_document,
    aws_dynamodb_table_item.records_protected,
  ]

  lifecycle {
    postcondition {
      condition     = try(jsondecode(self.result).error, "") == "AccessDenied"
      error_message = "Deployment check FAILED: the restricted read_document role was NOT denied the protected data (result: ${self.result}). The C2 IAM boundary is not real."
    }
  }
}

resource "aws_lambda_invocation" "probe_get_record" {
  function_name = aws_lambda_function.tool_get_record.function_name
  input         = jsonencode({ probe = "read_protected" })

  depends_on = [
    aws_s3_object.protected_document,
    aws_dynamodb_table_item.records_protected,
  ]

  lifecycle {
    postcondition {
      condition     = try(jsondecode(self.result).error, "") == "AccessDenied"
      error_message = "Deployment check FAILED: the restricted get_record role was NOT denied the protected data (result: ${self.result}). The C2 IAM boundary is not real."
    }
  }
}
