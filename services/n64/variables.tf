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

variable "server_hostname" {
  description = "Hostname/instance label for the coordinator EC2 node."
  type        = string
  default     = "paulnode-uswest2"
}

variable "tailscale_enabled" {
  description = "Install and configure Tailscale on the EC2 node."
  type        = bool
  default     = true
}

variable "tailscale_advertise_exit_node" {
  description = "Advertise this node as a Tailscale exit node."
  type        = bool
  default     = true
}

variable "tailscale_auth_key" {
  description = "Optional Tailscale auth key for unattended initial join. Leave empty if the node is already authenticated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "shared_proxy_enabled" {
  description = "Install and configure a shared reverse proxy for hosting multiple apps on this node."
  type        = bool
  default     = true
}

variable "shared_proxy_port" {
  description = "Port exposed by the shared reverse proxy for multi-tenant app routing."
  type        = number
  default     = 8080
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

variable "basic_auth_enabled" {
  description = "Enable CloudFront edge password gate for the whole site (frontend, API, and WebSocket paths)."
  type        = bool
  default     = true
}

variable "basic_auth_username" {
  description = "Deprecated legacy field from basic-auth mode. Kept for compatibility; leave empty."
  type        = string
  default     = ""
}

variable "basic_auth_password" {
  description = "Password for CloudFront edge password gate. Required when basic_auth_enabled=true."
  type        = string
  default     = ""
  sensitive   = true
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
