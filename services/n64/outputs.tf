output "site_domain_name" {
  description = "Primary HTTPS domain currently serving Warpdeck64"
  value       = var.enable_custom_domain ? var.domain_name : aws_cloudfront_distribution.site.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID for invalidations"
  value       = aws_cloudfront_distribution.site.id
}

output "cloudfront_distribution_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.site.domain_name
}

output "frontend_bucket_name" {
  description = "S3 bucket containing built frontend assets"
  value       = aws_s3_bucket.frontend.bucket
}

output "artifact_bucket_name" {
  description = "S3 bucket used for coordinator release bundles"
  value       = aws_s3_bucket.artifact.bucket
}

output "coordinator_instance_id" {
  description = "EC2 instance ID for SSM-based backend deployments"
  value       = aws_instance.coordinator.id
}

output "coordinator_public_ip" {
  description = "Public IP attached to the coordinator instance"
  value       = aws_eip.coordinator.public_ip
}

output "coordinator_origin_domain" {
  description = "CloudFront coordinator origin host"
  value       = aws_instance.coordinator.public_dns
}

output "coordinator_log_group_name" {
  description = "CloudWatch log group for coordinator process logs"
  value       = aws_cloudwatch_log_group.coordinator.name
}

output "shared_proxy_port" {
  description = "Port on the EC2 node used by the shared multi-tenant reverse proxy"
  value       = var.shared_proxy_enabled ? var.shared_proxy_port : null
}
