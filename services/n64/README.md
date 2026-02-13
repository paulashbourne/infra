# Warpdeck 64 Hosting Stack

Terraform stack for production hosting of `n64.paulashbourne.com`:

- CloudFront + private S3 static frontend
- EC2 `t4g.nano` multiplayer coordinator
- Same-origin routing (`/api/*` + `/ws/*`) to coordinator
- ACM certificate (us-east-1) + Route53 records
- CloudWatch log group + EC2 alarms

Domain transfer friendly mode:

- By default (`enable_custom_domain = false`), the stack serves via the CloudFront default domain (no DNS cutover required).
- When your domain transfer/delegation is ready, set `enable_custom_domain = true` to attach ACM + Route53 alias for `n64.paulashbourne.com`.

## Prerequisites

- Existing Route53 hosted zone for `paulashbourne.com`
- AWS credentials with permissions for Route53, ACM, CloudFront, EC2, IAM, S3, and CloudWatch
- Two globally unique S3 bucket names (frontend + backend artifacts)

## Usage

```bash
cd /Users/paul/git/paulashbourne/infra/services/n64

cat > terraform.tfvars <<TFVARS
aws_region           = "us-east-1"
enable_custom_domain = false
domain_name          = "n64.paulashbourne.com"
root_domain          = "paulashbourne.com"
frontend_bucket_name = "<globally-unique-frontend-bucket>"
artifact_bucket_name = "<globally-unique-artifact-bucket>"
basic_auth_enabled   = true
basic_auth_username  = "" # deprecated (legacy basic-auth field), keep empty
basic_auth_password  = "<strong-password>"
# Optional: pin subnet if your chosen instance type is not available in one AZ
# coordinator_subnet_id = "subnet-xxxxxxxx"
TFVARS

terraform init
terraform fmt
terraform validate
terraform plan
terraform apply
```

## Post-apply outputs to capture

```bash
terraform output site_domain_name
terraform output cloudfront_distribution_id
terraform output frontend_bucket_name
terraform output artifact_bucket_name
terraform output coordinator_instance_id
```

Use those outputs with deployment scripts in:

- `/Users/paul/git/paulashbourne/n64-emulator/scripts/deploy-frontend.sh`
- `/Users/paul/git/paulashbourne/n64-emulator/scripts/deploy-backend.sh`

## Notes

- This stack assumes local Terraform state (per current preference).
- With `enable_custom_domain = false`, use the `site_domain_name` output (CloudFront domain).
- With `enable_custom_domain = true`, `n64.paulashbourne.com` A/AAAA alias records override the wildcard DNS record.
- The EC2 coordinator only accepts inbound traffic from CloudFront origin-facing IP ranges.
- Password gate runs at CloudFront edge and protects frontend + `/api/*` + `/ws/*`.
- Unauthenticated users see a custom password page (no browser basic-auth modal).
- A successful login sets a long-lived secure cookie so the same device/browser does not prompt repeatedly.
- Shared URLs can include `?password=<value>` once to auto-unlock and then redirect to a clean URL.
