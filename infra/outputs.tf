output "region" {
  value = var.aws_region
}

output "cloudtrail_name" {
  value = aws_cloudtrail.trail.name
}

output "cloudtrail_s3_bucket" {
  value = aws_s3_bucket.cloudtrail.bucket
}

output "alerts_table_name" {
  value = aws_dynamodb_table.alerts.name
}

output "detector_lambda_name" {
  value = aws_lambda_function.detector.function_name
}

