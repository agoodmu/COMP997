# dynamodb.tf — the synthetic customer-record tables.
#
# Partition key "pk" (string). Fixtures use keys like "CUST#<alias>".
#
# The protected record (pk "CUST#protected", alias "__protected__") lives in
# its OWN table (protected_records). The restricted get_record Lambda role
# (C2/C4) is granted dynamodb:GetItem only on the main records table, so the
# protected record is unreachable to it by plain resource scoping -- no
# dynamodb:LeadingKeys condition needed. (An earlier revision used a single
# table with a LeadingKeys condition; the simulator evaluated it as allowed
# but DynamoDB denied every GetItem in practice, reproduced 2026-10-06, so
# the design was changed to table separation. Same security property.)
# Pay-per-request: no capacity planning needed for 325 scheduled observations.

resource "aws_dynamodb_table" "records" {
  name         = "${local.prefix}-records"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Study = local.prefix
  }
}

resource "aws_dynamodb_table" "protected_records" {
  name         = "${local.prefix}-protected-records"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Study = local.prefix
  }
}
