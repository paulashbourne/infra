# AGENTS.md

## Purpose
This repository manages personal infrastructure for `paulashbourne.com` and `paulashbourne.ca`, plus service-specific stacks (currently the RetroArena stack at `services/retroarena`).
The RetroArena stack can also manage additional custom domains (currently `retroarena.live`) that terminate on the same CloudFront distribution.

## Repo Layout
- `main.tf`, `variables.tf`, `versions.tf`: root DNS stack (Route53 hosted zones + records for base domains).
- `services/retroarena/`: RetroArena hosting stack (CloudFront, S3, EC2 coordinator, optional custom domain wiring).

## Portfolio Pulse Ingress Notes
- Root Terraform owns DNS for `portfoliopulse.paulashbourne.com`, pointing it at `paulnode-uswest2.tail9cc783.ts.net`.
- The HTTPS reverse proxy itself is live nginx config on `paulnode-uswest2`, not currently codified in this repo.
- Current upstream target: `http://paulbase.tail9cc783.ts.net:8788`.
- Live nginx config path: `/etc/nginx/conf.d/paulnode-tailnet-ingress.conf`.
- Durable ingress source: SSM document `paulnode-tailnet-ingress-reconcile`, run hourly by association `paulnode-tailnet-ingress-reconcile-hourly` (`2e0db787-7935-4c3d-8a4a-e16d5a4c55bf`).
- That SSM document rewrites `/etc/paulnode/tailnet-ingress/services.json` and regenerates `/etc/nginx/conf.d/paulnode-tailnet-ingress.conf`; editing either file only on the instance will be overwritten.
- The nginx wildcard certificate is managed by certbot on `paulnode-uswest2` using the `dns-route53` plugin.
- The `retroarena-coordinator-role` instance role must retain Route53 permissions for the `paulashbourne.com` and `paulashbourne.ca` hosted zones so certbot can create DNS-01 challenge TXT records.

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

## RetroArena TURN

`services/retroarena/turn.tf` owns two regional managed TURN channels (Oregon/Virginia), their CloudFormation wrappers, `/retroarena/turn/channels` SSM configuration and a scoped coordinator IAM policy. Existing web/coordinator resources are unchanged. These channels supply credentials only; do not migrate room signaling to Kinesis. Kinesis limits each allocation to 5 Mbps and each channel to 50 allocations. The application refreshes five-minute credentials and caps relayed video at 4 Mbps. Do not print ICE credentials or put them in Terraform state; only channel ARNs belong in the parameter.
