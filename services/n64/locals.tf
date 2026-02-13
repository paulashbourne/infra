locals {
  service_name = "warpdeck-n64"

  common_tags = merge(
    {
      Service   = local.service_name
      ManagedBy = "terraform"
    },
    var.tags,
  )
}
