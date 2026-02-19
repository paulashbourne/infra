provider "aws" {
  region = var.aws_region
}

locals {
  zone_names = toset([
    "paulashbourne.com",
    "paulashbourne.ca",
  ])

  # Keep paulashbourne.com email-only (iCloud Mail) records.
  records = [
    {
      zone    = "paulashbourne.com"
      name    = "sig1._domainkey.paulashbourne.com"
      type    = "CNAME"
      ttl     = 14400
      records = ["sig1.dkim.paulashbourne.com.at.icloudmailadmin.com."]
    },
    {
      zone = "paulashbourne.com"
      name = "paulashbourne.com"
      type = "MX"
      ttl  = 14400
      records = [
        "10 mx01.mail.icloud.com.",
        "10 mx02.mail.icloud.com.",
      ]
    },
    {
      zone = "paulashbourne.com"
      name = "paulashbourne.com"
      type = "TXT"
      ttl  = 14400
      records = [
        "apple-domain=HjMdfIZ3fhEcm9a8",
        "v=spf1 include:icloud.com ~all",
      ]
    },
    {
      zone    = "paulashbourne.ca"
      name    = "paulashbourne.ca"
      type    = "A"
      ttl     = 14400
      records = ["178.128.233.77"]
    },
    {
      zone    = "paulashbourne.ca"
      name    = "_domainconnect.paulashbourne.ca"
      type    = "CNAME"
      ttl     = 14400
      records = ["_domainconnect.domains.squarespace.com."]
    },
    {
      zone    = "paulashbourne.ca"
      name    = "efsbnbfjfly4.paulashbourne.ca"
      type    = "CNAME"
      ttl     = 14400
      records = ["gv-qm6mosamgrqq5s.dv.googlehosted.com."]
    },
  ]

  records_by_key = {
    for record in local.records :
    "${record.zone}|${record.name}|${record.type}" => record
  }
}

resource "aws_route53_zone" "zones" {
  for_each = local.zone_names
  name     = each.value
  comment  = "Managed by Terraform"
}

resource "aws_route53_record" "records" {
  for_each = local.records_by_key
  zone_id  = aws_route53_zone.zones[each.value.zone].zone_id
  name     = each.value.name
  type     = each.value.type
  ttl      = each.value.ttl
  records  = each.value.records
}

output "hosted_zone_ids" {
  value = {
    for zone_name, zone in aws_route53_zone.zones :
    zone_name => zone.zone_id
  }
}

output "nameservers" {
  value = {
    for zone_name, zone in aws_route53_zone.zones :
    zone_name => zone.name_servers
  }
}
