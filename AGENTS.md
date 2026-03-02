# AGENTS.md

## Purpose
This repository manages personal infrastructure for `paulashbourne.com` and `paulashbourne.ca`, plus service-specific stacks (currently the RetroArena stack at `services/retroarena`).
The RetroArena stack can also manage additional custom domains (currently `retroarena.live`) that terminate on the same CloudFront distribution.

## Repo Layout
- `main.tf`, `variables.tf`, `versions.tf`: root DNS stack (Route53 hosted zones + records for base domains).
- `services/retroarena/`: RetroArena hosting stack (CloudFront, S3, EC2 coordinator, optional custom domain wiring).

## Terraform Conventions
- Terraform is run with local state in this repo.
- Use `terraform fmt`, `terraform validate`, and `terraform plan` before apply.
- Root stack:
  - `terraform init`
  - `terraform plan`
  - `terraform apply`
- RetroArena stack:
  - `terraform -chdir=services/retroarena init`
  - `terraform -chdir=services/retroarena plan`
  - `terraform -chdir=services/retroarena apply`

## DNS Safety Rules
- Never change registrar nameservers until Route53 records are parity-checked against current public DNS.
- Validate both:
  - Public resolver answers (`dig +short <name> <type>`)
  - Route53 authoritative answers (`dig +short @<route53-ns> <name> <type>`)
- For the RetroArena stack (`services/retroarena`), custom domain records are conditional:
  - `enable_custom_domain = false` means no app domain Route53 alias records are created.
  - `enable_custom_domain = true` + `additional_custom_domains = { "retroarena.live" = "retroarena.live" }` keeps `n64.paulashbourne.ca` active and also routes `retroarena.live` to the same CloudFront distribution with ACM SAN coverage.

## Credentials and Access
- AWS account in use: `928352318751`.
- Prefer `us-east-1` for Route53 Domains and RetroArena stack operations (`services/retroarena`).
- If Terraform cannot read CLI login credentials, export credentials in-shell first:
  - `eval "$(aws configure export-credentials --format env)"`

## SSH Notes (RetroArena Coordinator)
- EC2 coordinator currently supports SSH via `ec2-user` using local key auth.
- Manual SG rules can be overwritten by future Terraform applies in `services/retroarena`.
- If preserving SSH access is required long-term, codify ingress rules in Terraform.

## Commit Hygiene
- Do not commit generated artifacts:
  - `.terraform/`, `tfplan`, `*.tfstate`, `*.tfstate.*`
- Keep commits scoped to task intent.
- Do not include unrelated file changes unless explicitly requested.
