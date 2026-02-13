locals {
  service_name            = "warpdeck-n64"
  basic_auth_active       = var.basic_auth_enabled && trimspace(var.basic_auth_password) != ""
  basic_auth_cookie_name  = "wd64_auth"
  basic_auth_cookie_token = local.basic_auth_active ? sha256("${local.service_name}:${var.basic_auth_password}") : ""

  common_tags = merge(
    {
      Service   = local.service_name
      ManagedBy = "terraform"
    },
    var.tags,
  )
}
