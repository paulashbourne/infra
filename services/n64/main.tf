data "aws_route53_zone" "root" {
  name         = "${var.root_domain}."
  private_zone = false
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ssm_parameter" "al2023_arm64_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_ec2_managed_prefix_list" "cloudfront_origin_facing" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_s3_bucket" "frontend" {
  bucket = var.frontend_bucket_name
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "artifact" {
  bucket = var.artifact_bucket_name
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifact" {
  bucket = aws_s3_bucket.artifact.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudwatch_log_group" "coordinator" {
  name              = "/warpdeck/n64/coordinator"
  retention_in_days = var.cloudwatch_log_retention_days
  tags              = local.common_tags
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "coordinator" {
  name               = "warpdeck-n64-coordinator-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "coordinator_ssm_core" {
  role       = aws_iam_role.coordinator.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "coordinator_runtime" {
  statement {
    sid = "AllowCoordinatorLogWrites"

    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]

    resources = [
      aws_cloudwatch_log_group.coordinator.arn,
      "${aws_cloudwatch_log_group.coordinator.arn}:*",
    ]
  }

  statement {
    sid = "AllowArtifactBucketRead"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]

    resources = ["${aws_s3_bucket.artifact.arn}/*"]
  }

  statement {
    sid = "AllowArtifactBucketList"

    actions = [
      "s3:ListBucket",
    ]

    resources = [aws_s3_bucket.artifact.arn]
  }
}

resource "aws_iam_role_policy" "coordinator_runtime" {
  name   = "warpdeck-n64-coordinator-runtime"
  role   = aws_iam_role.coordinator.id
  policy = data.aws_iam_policy_document.coordinator_runtime.json
}

resource "aws_iam_instance_profile" "coordinator" {
  name = "warpdeck-n64-coordinator-instance-profile"
  role = aws_iam_role.coordinator.name
}

resource "aws_security_group" "coordinator" {
  name        = "warpdeck-n64-coordinator"
  description = "Allow multiplayer coordinator traffic only from CloudFront origin network"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "CloudFront origin-facing network"
    from_port       = var.coordinator_port
    to_port         = var.coordinator_port
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront_origin_facing.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_instance" "coordinator" {
  ami                         = data.aws_ssm_parameter.al2023_arm64_ami.value
  instance_type               = var.instance_type
  subnet_id                   = var.coordinator_subnet_id != "" ? var.coordinator_subnet_id : data.aws_subnets.default.ids[0]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.coordinator.id]
  iam_instance_profile        = aws_iam_instance_profile.coordinator.name

  user_data = templatefile("${path.module}/user_data.sh.tmpl", {
    aws_region                 = var.aws_region
    coordinator_port           = var.coordinator_port
    coordinator_log_group_name = aws_cloudwatch_log_group.coordinator.name
    artifact_bucket_name       = var.artifact_bucket_name
  })

  tags = merge(local.common_tags, {
    Name = "warpdeck-n64-coordinator"
  })
}

resource "aws_eip" "coordinator" {
  domain = "vpc"
  tags   = local.common_tags
}

resource "aws_eip_association" "coordinator" {
  allocation_id = aws_eip.coordinator.id
  instance_id   = aws_instance.coordinator.id
}

resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "warpdeck-n64-frontend-oac"
  description                       = "OAC for Warpdeck64 static frontend"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_acm_certificate" "site" {
  count             = var.enable_custom_domain ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

resource "aws_route53_record" "site_cert_validation" {
  for_each = var.enable_custom_domain ? {
    for dvo in aws_acm_certificate.site[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  zone_id         = data.aws_route53_zone.root.zone_id
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
}

resource "aws_acm_certificate_validation" "site" {
  count           = var.enable_custom_domain ? 1 : 0
  provider        = aws.us_east_1
  certificate_arn = aws_acm_certificate.site[0].arn
  validation_record_fqdns = [
    for record in aws_route53_record.site_cert_validation : record.fqdn
  ]
}

resource "aws_cloudfront_function" "spa_rewrite" {
  name    = "warpdeck-n64-spa-rewrite"
  runtime = "cloudfront-js-1.0"
  publish = true
  comment = "Rewrite extensionless paths to /index.html for SPA routing"

  code = <<-EOT
    function handler(event) {
      var request = event.request;
      var uri = request.uri;

      if (uri.endsWith('/')) {
        request.uri = uri + 'index.html';
        return request;
      }

      if (uri.indexOf('.') === -1) {
        request.uri = '/index.html';
      }

      return request;
    }
  EOT
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Warpdeck64 single-domain frontend + multiplayer coordinator"
  aliases             = var.enable_custom_domain ? [var.domain_name] : []
  price_class         = "PriceClass_100"
  default_root_object = "index.html"
  http_version        = "http2and3"

  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "frontend-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  origin {
    domain_name = aws_instance.coordinator.public_dns
    origin_id   = "coordinator-http"

    custom_origin_config {
      http_port                = var.coordinator_port
      https_port               = 443
      origin_protocol_policy   = "http-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 60
    }
  }

  default_cache_behavior {
    target_origin_id       = "frontend-s3"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id = data.aws_cloudfront_cache_policy.caching_optimized.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
  }

  ordered_cache_behavior {
    path_pattern           = "api/*"
    target_origin_id       = "coordinator-http"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    allowed_methods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  ordered_cache_behavior {
    path_pattern           = "ws/*"
    target_origin_id       = "coordinator-http"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn            = var.enable_custom_domain ? aws_acm_certificate_validation.site[0].certificate_arn : null
    ssl_support_method             = var.enable_custom_domain ? "sni-only" : null
    minimum_protocol_version       = var.enable_custom_domain ? "TLSv1.2_2021" : "TLSv1"
    cloudfront_default_certificate = var.enable_custom_domain ? false : true
  }

  tags = local.common_tags
}

data "aws_iam_policy_document" "frontend_bucket_policy" {
  statement {
    sid = "AllowCloudFrontRead"

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions = ["s3:GetObject"]

    resources = ["${aws_s3_bucket.frontend.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = data.aws_iam_policy_document.frontend_bucket_policy.json
}

resource "aws_route53_record" "site_a" {
  count   = var.enable_custom_domain ? 1 : 0
  zone_id = data.aws_route53_zone.root.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "site_aaaa" {
  count   = var.enable_custom_domain ? 1 : 0
  zone_id = data.aws_route53_zone.root.zone_id
  name    = var.domain_name
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_cloudwatch_metric_alarm" "status_check_failed" {
  alarm_name          = "warpdeck-n64-ec2-status-check-failed"
  alarm_description   = "Status check failures on Warpdeck64 multiplayer coordinator"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = aws_instance.coordinator.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count = var.enable_cpu_alarm ? 1 : 0

  alarm_name          = "warpdeck-n64-ec2-cpu-high"
  alarm_description   = "Coordinator CPU > 80% for 15 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = aws_instance.coordinator.id
  }

  tags = local.common_tags
}
