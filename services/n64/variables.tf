variable "aws_region" {
  description = "AWS region for regional resources (EC2, S3, Route53 records)."
  type        = string
  default     = "us-east-1"
}

variable "root_domain" {
  description = "Route53 hosted zone root domain (used when enable_custom_domain=true)."
  type        = string
  default     = "paulashbourne.com"
}

variable "domain_name" {
  description = "Public application domain served by CloudFront when enable_custom_domain=true."
  type        = string
  default     = "n64.paulashbourne.com"
}

variable "enable_custom_domain" {
  description = "Attach ACM + Route53 alias for var.domain_name. Keep false until domain delegation is ready."
  type        = bool
  default     = false
}

variable "frontend_bucket_name" {
  description = "Global-unique S3 bucket name for static frontend assets."
  type        = string
}

variable "artifact_bucket_name" {
  description = "Global-unique S3 bucket name for backend release artifacts."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for multiplayer coordinator."
  type        = string
  default     = "t4g.nano"
}

variable "coordinator_subnet_id" {
  description = "Optional subnet ID for the coordinator instance. Set this when a specific AZ is required for the selected instance type."
  type        = string
  default     = ""
}

variable "coordinator_port" {
  description = "Coordinator HTTP/WebSocket port exposed to CloudFront origin traffic."
  type        = number
  default     = 8787
}

variable "cloudwatch_log_retention_days" {
  description = "Retention window for coordinator CloudWatch logs."
  type        = number
  default     = 14
}

variable "enable_cpu_alarm" {
  description = "Whether to create a high-CPU CloudWatch alarm."
  type        = bool
  default     = true
}

variable "alarm_actions" {
  description = "SNS topic ARNs or other alarm action ARNs. Leave empty for dashboard-only alarms."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags to apply to resources."
  type        = map(string)
  default     = {}
}
