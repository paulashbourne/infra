locals {
  service_name              = "warpdeck-n64"
  basic_auth_active         = var.basic_auth_enabled && trimspace(var.basic_auth_password) != ""
  basic_auth_cookie_name    = "wd64_auth"
  basic_auth_cookie_token   = local.basic_auth_active ? sha256("${local.service_name}:${var.basic_auth_password}") : ""
  coordinator_s3_enabled    = trimspace(var.coordinator_s3_bucket_name) != ""
  coordinator_s3_region     = trimspace(var.coordinator_s3_region) != "" ? trimspace(var.coordinator_s3_region) : var.aws_region
  coordinator_s3_prefix     = trim(trimspace(var.coordinator_s3_key_prefix), "/")
  coordinator_s3_bucket_arn = local.coordinator_s3_enabled ? "arn:aws:s3:::${var.coordinator_s3_bucket_name}" : ""
  coordinator_s3_object_arn = local.coordinator_s3_enabled ? (
    local.coordinator_s3_prefix != ""
    ? "arn:aws:s3:::${var.coordinator_s3_bucket_name}/${local.coordinator_s3_prefix}/*"
    : "arn:aws:s3:::${var.coordinator_s3_bucket_name}/*"
  ) : ""

  common_tags = merge(
    {
      Service   = local.service_name
      ManagedBy = "terraform"
    },
    var.tags,
  )
}
