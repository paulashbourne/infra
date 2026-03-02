locals {
  service_name            = "retroarena"
  basic_auth_active       = var.basic_auth_enabled && trimspace(var.basic_auth_password) != ""
  basic_auth_cookie_name  = "retroarena_auth"
  basic_auth_cookie_token = local.basic_auth_active ? sha256("${local.service_name}:${var.basic_auth_password}") : ""
  normalized_root_domain  = trimsuffix(trimspace(var.root_domain), ".")
  primary_domain_name     = trimsuffix(trimspace(var.domain_name), ".")

  additional_custom_domains = {
    for domain_name, zone_name in var.additional_custom_domains :
    trimsuffix(trimspace(domain_name), ".") => trimsuffix(trimspace(zone_name), ".")
    if trimspace(domain_name) != "" && trimspace(zone_name) != ""
  }

  additional_domain_names = sort(keys(local.additional_custom_domains))
  additional_zone_names = toset([
    for zone_name in values(local.additional_custom_domains) : zone_name
    if zone_name != local.normalized_root_domain
  ])

  site_aliases = var.enable_custom_domain ? [local.primary_domain_name] : []

  domain_zone_by_domain_name = merge(
    { (local.primary_domain_name) = local.normalized_root_domain },
    local.additional_custom_domains,
  )

  custom_zone_ids = merge(
    { (local.normalized_root_domain) = data.aws_route53_zone.root.zone_id },
    { for zone_name, zone in data.aws_route53_zone.additional_roots : zone_name => zone.zone_id },
  )

  site_cert_validation_records = var.enable_custom_domain ? {
    for dvo in aws_acm_certificate.site[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
      zone_name = one([
        for domain_name, zone_name in local.domain_zone_by_domain_name :
        zone_name if dvo.domain_name == domain_name || endswith(dvo.domain_name, ".${zone_name}")
      ])
    }
  } : {}

  common_tags = merge(
    {
      Service   = local.service_name
      ManagedBy = "terraform"
    },
    var.tags,
  )
}
