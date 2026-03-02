provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "ctd-lab-${data.aws_caller_identity.current.account_id}"
}

# --- S3 bucket for CloudTrail logs ---
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${local.name_prefix}-cloudtrail-logs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

# CloudTrail needs a bucket policy
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  # CloudTrail checks bucket ACL
  statement {
    sid = "AWSCloudTrailAclCheck"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLocation"
    ]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  # CloudTrail writes logs into AWSLogs/<account-id>/
  statement {
    sid = "AWSCloudTrailWrite"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# --- CloudTrail trail (management events) ---
resource "aws_cloudtrail" "trail" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_s3_bucket_public_access_block.cloudtrail
  ]
}

# --- DynamoDB table to store alerts ---
resource "aws_dynamodb_table" "alerts" {
  name         = "${local.name_prefix}-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_id"

  attribute {
    name = "alert_id"
    type = "S"
  }
}

# --- Lambda function (EventBridge target later) ---
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/detector.py"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_iam_role" "lambda_role" {
  name = "${local.name_prefix}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "dynamodb:PutItem"
        ],
        Resource = aws_dynamodb_table.alerts.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "detector" {
  function_name = "${local.name_prefix}-detector"
  role          = aws_iam_role.lambda_role.arn
  handler       = "detector.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      ALERTS_TABLE = aws_dynamodb_table.alerts.name
    }
  }
}

# --- EventBridge Rule: Detect suspicious IAM CreateAccessKey calls via CloudTrail ---
resource "aws_cloudwatch_event_rule" "detect_create_access_key" {
  name        = "${local.name_prefix}-detect-create-access-key"
  description = "Detect IAM CreateAccessKey events via CloudTrail"

  # Matches CloudTrail management events that are routed to EventBridge
  event_pattern = jsonencode({
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["iam.amazonaws.com"],
      "eventName": ["CreateAccessKey"]
    }
  })
}

# Allow EventBridge to invoke the Lambda for CreateAccessKey
resource "aws_lambda_permission" "allow_eventbridge_invoke_create_access_key" {
  statement_id  = "AllowExecutionFromEventBridgeCreateAccessKey"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_create_access_key.arn
}

# Connect rule to Lambda target
resource "aws_cloudwatch_event_target" "create_access_key_to_lambda" {
  rule      = aws_cloudwatch_event_rule.detect_create_access_key.name
  target_id = "SendToDetectorLambda"
  arn       = aws_lambda_function.detector.arn
}

# --- EventBridge Rule: Detect IAM DeleteAccessKey calls via CloudTrail ---
resource "aws_cloudwatch_event_rule" "detect_delete_access_key" {
  name        = "${local.name_prefix}-detect-delete-access-key"
  description = "Detect IAM DeleteAccessKey events via CloudTrail"

  event_pattern = jsonencode({
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["iam.amazonaws.com"],
      "eventName": ["DeleteAccessKey"]
    }
  })
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_delete_access_key" {
  statement_id  = "AllowExecutionFromEventBridgeDeleteAccessKey"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_delete_access_key.arn
}

resource "aws_cloudwatch_event_target" "delete_access_key_to_lambda" {
  rule      = aws_cloudwatch_event_rule.detect_delete_access_key.name
  target_id = "SendToDetectorLambdaDeleteAccessKey"
  arn       = aws_lambda_function.detector.arn
}

# --- EventBridge Rule: Detect CloudTrail tampering (StopLogging / DeleteTrail / UpdateTrail) ---
resource "aws_cloudwatch_event_rule" "detect_cloudtrail_tampering" {
  name        = "${local.name_prefix}-detect-cloudtrail-tampering"
  description = "Detect attempts to disable or modify CloudTrail via CloudTrail API calls"

  event_pattern = jsonencode({
    "source": ["aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["cloudtrail.amazonaws.com"],
      "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail"]
    }
  })
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_cloudtrail_tampering" {
  statement_id  = "AllowExecutionFromEventBridgeCloudTrailTampering"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_cloudtrail_tampering.arn
}

resource "aws_cloudwatch_event_target" "cloudtrail_tampering_to_lambda" {
  rule      = aws_cloudwatch_event_rule.detect_cloudtrail_tampering.name
  target_id = "SendToDetectorLambdaCloudTrailTampering"
  arn       = aws_lambda_function.detector.arn
}

# --- EventBridge Rule: Detect KMS key deletion scheduling ---
resource "aws_cloudwatch_event_rule" "detect_kms_schedule_key_deletion" {
  name        = "${local.name_prefix}-detect-kms-schedule-key-deletion"
  description = "Detect KMS ScheduleKeyDeletion calls via CloudTrail"

  event_pattern = jsonencode({
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["kms.amazonaws.com"],
      "eventName": ["ScheduleKeyDeletion"]
    }
  })
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_kms_schedule_key_deletion" {
  statement_id  = "AllowExecutionFromEventBridgeKMSScheduleKeyDeletion"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_kms_schedule_key_deletion.arn
}

resource "aws_cloudwatch_event_target" "kms_schedule_key_deletion_to_lambda" {
  rule      = aws_cloudwatch_event_rule.detect_kms_schedule_key_deletion.name
  target_id = "SendToDetectorLambdaKMSScheduleKeyDeletion"
  arn       = aws_lambda_function.detector.arn
}

# --- EventBridge Rule: Scheduled test trigger (every 2 minutes) ---
resource "aws_cloudwatch_event_rule" "test_schedule" {
  name                = "${local.name_prefix}-test-schedule"
  description         = "Scheduled rule to test EventBridge -> Lambda"
  schedule_expression = "rate(2 minutes)"
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_test_schedule" {
  statement_id  = "AllowExecutionFromEventBridgeTestSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.test_schedule.arn
}

resource "aws_cloudwatch_event_target" "test_schedule_to_lambda" {
  rule      = aws_cloudwatch_event_rule.test_schedule.name
  target_id = "SendToDetectorLambdaSchedule"
  arn       = aws_lambda_function.detector.arn
}