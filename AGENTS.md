# AGENTS.md

## Purpose
This repository manages personal infrastructure for `paulashbourne.com` and `paulashbourne.ca`, plus service-specific stacks (currently `services/n64`).

## Repo Layout
- `main.tf`, `variables.tf`, `versions.tf`: root DNS stack (Route53 hosted zones + records).
- `services/n64/`: Warpdeck 64 hosting stack (CloudFront, S3, EC2 coordinator, optional custom domain wiring).

## Terraform Conventions
- Terraform is run with local state in this repo.
- Use `terraform fmt`, `terraform validate`, and `terraform plan` before apply.
- Root stack:
  - `terraform init`
  - `terraform plan`
  - `terraform apply`
- N64 stack:
  - `terraform -chdir=services/n64 init`
  - `terraform -chdir=services/n64 plan`
  - `terraform -chdir=services/n64 apply`

## DNS Safety Rules
- Never change registrar nameservers until Route53 records are parity-checked against current public DNS.
- Validate both:
  - Public resolver answers (`dig +short <name> <type>`)
  - Route53 authoritative answers (`dig +short @<route53-ns> <name> <type>`)
- For `services/n64`, custom domain records are conditional:
  - `enable_custom_domain = false` means no `n64.paulashbourne.com` Route53 alias records are created.

## Credentials and Access
- AWS account in use: `928352318751`.
- Prefer `us-east-1` for Route53 Domains and `services/n64` operations.
- If Terraform cannot read CLI login credentials, export credentials in-shell first:
  - `eval "$(aws configure export-credentials --format env)"`

## SSH Notes (N64 Coordinator)
- EC2 coordinator currently supports SSH via `ec2-user` using local key auth.
- Manual SG rules can be overwritten by future Terraform applies in `services/n64`.
- If preserving SSH access is required long-term, codify ingress rules in Terraform.

## Commit Hygiene
- Do not commit generated artifacts:
  - `.terraform/`, `tfplan`, `*.tfstate`, `*.tfstate.*`
- Keep commits scoped to task intent.
- Do not include unrelated file changes unless explicitly requested.
