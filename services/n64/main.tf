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

resource "aws_security_group" "coordinator_shared_proxy" {
  count       = var.shared_proxy_enabled && var.shared_proxy_port != var.coordinator_port ? 1 : 0
  name        = "warpdeck-n64-coordinator-shared-proxy"
  description = "Allow shared tenant proxy traffic from CloudFront origin network"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "CloudFront origin-facing network (shared proxy)"
    from_port       = var.shared_proxy_port
    to_port         = var.shared_proxy_port
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
  vpc_security_group_ids = var.shared_proxy_enabled && var.shared_proxy_port != var.coordinator_port ? concat(
    [aws_security_group.coordinator.id],
    aws_security_group.coordinator_shared_proxy[*].id
  ) : [aws_security_group.coordinator.id]
  iam_instance_profile = aws_iam_instance_profile.coordinator.name

  user_data = templatefile("${path.module}/user_data.sh.tmpl", {
    aws_region                    = var.aws_region
    server_hostname               = var.server_hostname
    tailscale_enabled             = var.tailscale_enabled
    tailscale_advertise_exit_node = var.tailscale_advertise_exit_node
    tailscale_auth_key            = var.tailscale_auth_key
    shared_proxy_enabled          = var.shared_proxy_enabled
    shared_proxy_port             = var.shared_proxy_port
    coordinator_port              = var.coordinator_port
    coordinator_log_group_name    = aws_cloudwatch_log_group.coordinator.name
    artifact_bucket_name          = var.artifact_bucket_name
    basic_auth_cookie_name        = local.basic_auth_cookie_name
    basic_auth_cookie_token       = local.basic_auth_cookie_token
  })

  lifecycle {
    precondition {
      condition     = !(var.shared_proxy_enabled && var.shared_proxy_port == var.coordinator_port)
      error_message = "shared_proxy_port must differ from coordinator_port when shared_proxy_enabled."
    }
  }

  tags = merge(local.common_tags, {
    Name = var.server_hostname
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
  comment = "Password gate + SPA rewrite for Warpdeck64"

  code = <<-EOT
    function handler(event) {
      var request = event.request;
      var authEnabled = ${local.basic_auth_active ? "true" : "false"};
      var expectedPassword = ${jsonencode(trimspace(var.basic_auth_password))};
      var cookieName = ${jsonencode(local.basic_auth_cookie_name)};
      var cookieToken = ${jsonencode(local.basic_auth_cookie_token)};

      function parseCookieValue(cookieHeader, name) {
        if (!cookieHeader || !cookieHeader.value) {
          return '';
        }

        var prefix = name + '=';
        var pairs = cookieHeader.value.split(';');
        for (var i = 0; i < pairs.length; i++) {
          var cookie = pairs[i].trim();
          if (cookie.indexOf(prefix) === 0) {
            return cookie.substring(prefix.length);
          }
        }
        return '';
      }

      function hasAuthCookie(request) {
        if (request.cookies && request.cookies[cookieName] && request.cookies[cookieName].value) {
          return request.cookies[cookieName].value === cookieToken;
        }
        return parseCookieValue(request.headers.cookie, cookieName) === cookieToken;
      }

      function isPasswordKey(key) {
        var lowered = (key || '').toLowerCase();
        return lowered === 'password' || lowered === 'pw' || lowered === 'pass' || lowered === 'p';
      }

      function valuesFromQueryEntry(entry) {
        if (!entry) {
          return [];
        }

        if (entry.multiValue && entry.multiValue.length > 0) {
          var values = [];
          for (var index = 0; index < entry.multiValue.length; index++) {
            var multi = entry.multiValue[index];
            if (multi && multi.value !== undefined) {
              values.push(String(multi.value));
            }
          }
          return values;
        }

        if (entry.value !== undefined) {
          return [String(entry.value)];
        }

        return [];
      }

      function decodeQueryValue(value) {
        if (value === undefined || value === null) {
          return '';
        }

        var text = String(value);
        if (text.length === 0) {
          return '';
        }

        // Form/query submissions can arrive URL-encoded at the edge.
        // Normalize '+' to spaces before decoding for compatibility.
        var normalized = text.replace(/\+/g, ' ');
        try {
          return decodeURIComponent(normalized);
        } catch (error) {
          return normalized;
        }
      }

      function getPasswordFromQuery(query) {
        if (!query) {
          return '';
        }

        for (var key in query) {
          if (!Object.prototype.hasOwnProperty.call(query, key) || !isPasswordKey(key)) {
            continue;
          }
          var values = valuesFromQueryEntry(query[key]);
          for (var valueIndex = 0; valueIndex < values.length; valueIndex++) {
            var decoded = decodeQueryValue(values[valueIndex]);
            if (decoded) {
              return decoded;
            }
          }
        }

        return '';
      }

      function buildQueryString(query) {
        var parts = [];
        for (var key in query) {
          if (!Object.prototype.hasOwnProperty.call(query, key)) {
            continue;
          }
          var entry = query[key];
          if (entry && entry.multiValue && entry.multiValue.length > 0) {
            for (var i = 0; i < entry.multiValue.length; i++) {
              var multi = entry.multiValue[i];
              if (multi && multi.value !== undefined) {
                parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(multi.value));
              }
            }
            continue;
          }

          if (entry && entry.value !== undefined) {
            parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(entry.value));
          }
        }
        return parts.join('&');
      }

      function copyQueryWithoutPassword(query) {
        var copy = {};
        if (!query) {
          return copy;
        }

        for (var key in query) {
          if (Object.prototype.hasOwnProperty.call(query, key)) {
            if (isPasswordKey(key)) {
              continue;
            }
            copy[key] = query[key];
          }
        }
        return copy;
      }

      function locationFor(request, query) {
        var built = buildQueryString(query);
        return (request.uri || '/') + (built.length > 0 ? '?' + built : '');
      }

      function escapeHtml(value) {
        if (value === undefined || value === null) {
          return '';
        }
        return String(value)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/\"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function buildHiddenFields(query) {
        var html = '';
        for (var key in query) {
          if (!Object.prototype.hasOwnProperty.call(query, key)) {
            continue;
          }
          var values = valuesFromQueryEntry(query[key]);
          for (var index = 0; index < values.length; index++) {
            html += '<input type=\"hidden\" name=\"' + escapeHtml(key) + '\" value=\"' + escapeHtml(values[index]) + '\">';
          }
        }
        return html;
      }

      function passwordPage(request, showError) {
        var cleanQuery = copyQueryWithoutPassword(request.querystring || {});
        var hiddenFields = buildHiddenFields(cleanQuery);
        var attemptedMessage = showError
          ? '<p class=\"error\">That password did not match. Try again.</p>'
          : '<p class=\"hint\">Enter the shared password to continue.</p>';
        var page = ''
          + '<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">'
          + '<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">'
          + '<title>Warpdeck 64 Access</title>'
          + '<style>'
          + ':root{color-scheme:dark;}'
          + 'body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 700px at 12% 8%,#0f6674 0%,transparent 55%),radial-gradient(1000px 700px at 92% 88%,#7f3e1d 0%,transparent 60%),#060a17;color:#f3f5ff;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Inter,Roboto,sans-serif;}'
          + '.card{width:min(430px,92vw);padding:28px 24px 22px;border-radius:16px;background:linear-gradient(180deg,rgba(22,27,52,.95),rgba(11,15,33,.95));border:1px solid rgba(126,161,235,.24);box-shadow:0 18px 50px rgba(0,0,0,.45);}'
          + '.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#8ea0d0;font-weight:700;}'
          + 'h1{margin:6px 0 8px;font-size:30px;line-height:1.05;}'
          + 'p{margin:0 0 14px;color:#c6cee9;font-size:15px;line-height:1.35;}'
          + '.hint{color:#b7c2e6;}'
          + '.error{color:#ff7f9d;font-weight:600;}'
          + 'label{display:block;margin:16px 0 8px;font-size:13px;color:#a8b5db;font-weight:600;}'
          + 'input{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:10px;border:1px solid rgba(126,161,235,.28);background:#0b1024;color:#f3f5ff;font-size:16px;outline:none;}'
          + 'input:focus{border-color:#6bcce2;box-shadow:0 0 0 2px rgba(62,172,205,.2);}'
          + 'button{margin-top:14px;width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(252,180,67,.35);background:linear-gradient(180deg,#283349,#171f34);color:#f0f3ff;font-size:15px;font-weight:700;cursor:pointer;}'
          + 'button:hover{border-color:rgba(252,180,67,.62);}'
          + '.meta{margin-top:12px;font-size:12px;color:#8f9cc4;}'
          + '.path{word-break:break-all;color:#7ecde0;}'
          + '</style></head><body>'
          + '<main class=\"card\">'
          + '<div class=\"eyebrow\">Browser N64 Emulator</div>'
          + '<h1>Warpdeck 64</h1>'
          + attemptedMessage
          + '<form method=\"get\" action=\"' + escapeHtml(request.uri || '/') + '\">'
          + hiddenFields
          + '<label for=\"password\">Password</label>'
          + '<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" autofocus required>'
          + '<button type=\"submit\">Enter Warpdeck</button>'
          + '</form>'
          + '</main></body></html>';

        return {
          statusCode: 200,
          statusDescription: 'OK',
          headers: {
            'content-type': { value: 'text/html; charset=utf-8' },
            'cache-control': { value: 'no-store, no-cache, must-revalidate' }
          },
          body: page
        };
      }

      if (authEnabled && expectedPassword.length > 0) {
        var query = request.querystring || {};
        var providedPassword = getPasswordFromQuery(query);
        var hasCookie = hasAuthCookie(request);
        var hasValidPassword = providedPassword !== '' && providedPassword === expectedPassword;
        var hasPasswordAttempt = providedPassword !== '';
        var cleanQuery = copyQueryWithoutPassword(query);
        var method = request.method || 'GET';
        var isReadMethod = method === 'GET' || method === 'HEAD';
        var uriForAuth = request.uri || '/';
        var isApiRoute = uriForAuth.indexOf('/api/') === 0;
        var isWsRoute = uriForAuth.indexOf('/ws/') === 0;

        if (!hasCookie && hasValidPassword && isReadMethod) {
          var cookieResponse = {
            statusCode: 302,
            statusDescription: 'Found',
            headers: {
              location: { value: locationFor(request, cleanQuery) },
              'cache-control': { value: 'no-store' }
            },
            cookies: {}
          };
          cookieResponse.cookies[cookieName] = {
            value: cookieToken,
            attributes: 'Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax'
          };
          return cookieResponse;
        }

        if (hasCookie && hasPasswordAttempt && isReadMethod) {
          return {
            statusCode: 302,
            statusDescription: 'Found',
            headers: {
              location: { value: locationFor(request, cleanQuery) },
              'cache-control': { value: 'no-store' }
            }
          };
        }

        if (!hasCookie) {
          if (isApiRoute || isWsRoute || !isReadMethod) {
            return {
              statusCode: 401,
              statusDescription: 'Unauthorized',
              headers: {
                'content-type': { value: 'application/json; charset=utf-8' },
                'cache-control': { value: 'no-store' }
              },
              body: '{\"error\":\"Password required.\"}'
            };
          }

          return passwordPage(request, hasPasswordAttempt && !hasValidPassword);
        }
      }

      var uri = request.uri || '/';
      if (uri.indexOf('/api/') === 0 || uri.indexOf('/ws/') === 0) {
        return request;
      }

      if (uri.charAt(uri.length - 1) === '/') {
        request.uri = uri + 'index.html';
        return request;
      }

      if (uri.indexOf('.') === -1) {
        request.uri = '/index.html';
      }

      return request;
    }
  EOT

  lifecycle {
    precondition {
      condition     = !var.basic_auth_enabled || trimspace(var.basic_auth_password) != ""
      error_message = "Set basic_auth_password when basic_auth_enabled=true."
    }
  }
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

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
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

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
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
