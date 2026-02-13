variable "aws_region" {
  description = "AWS region for provider operations. Route53 is global, but the AWS provider still needs a region."
  type        = string
  default     = "us-east-1"
}
