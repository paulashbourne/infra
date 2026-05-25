# paulashbourne infra

Route53 DNS bootstrap for:

- `paulashbourne.com`
- `paulashbourne.ca`

Service stacks:

- `services/retroarena` for RetroArena app hosting (`retroarena.live` with optional legacy aliases like `n64.paulashbourne.ca`)
- SES sender-domain DNS for Portfolio Pulse email notifications (`portfoliopulse.paulashbourne.com`)

## What this creates

- Two Route53 public hosted zones (one per domain)
- DNS records mirrored from current production DNS to avoid downtime during registrar transfer
- SES domain identity DNS records for `portfoliopulse.paulashbourne.com` (verification + DKIM)

## Portfolio Pulse ingress

Terraform points `portfoliopulse.paulashbourne.com` at the tailnet ingress node `paulnode-uswest2.tail9cc783.ts.net`.
The actual HTTPS reverse proxy is live nginx config on that node at `/etc/nginx/conf.d/paulnode-tailnet-ingress.conf`.
It currently forwards to the dashboard on `http://paulbase.tail9cc783.ts.net:8788`.
The generated nginx file is rebuilt by `refresh-policy-routes@ens5.timer` from `/etc/paulnode/tailnet-ingress/services.json`, so update that JSON source before reloading nginx when changing the Portfolio Pulse upstream.
TLS for the ingress is a certbot wildcard certificate on `paulnode-uswest2`; the coordinator instance role includes Route53 DNS-01 permissions for the `paulashbourne.com` and `paulashbourne.ca` zones so renewal can update challenge TXT records.

## Usage

```bash
# Optional (useful for AWS CLI v2 login sessions):
eval "$(aws configure export-credentials --format env)"

terraform init
terraform fmt
terraform validate
terraform plan
terraform apply
```

## Verification

After apply, use the output nameservers to verify records before changing domain delegation:

```bash
terraform output nameservers
aws route53 list-resource-record-sets --hosted-zone-id <ZONE_ID>
dig @<ROUTE53_NS> paulashbourne.com A +short
dig @<ROUTE53_NS> paulashbourne.ca A +short
```

## Cutover checklist

1. Apply this Terraform and verify all answers from Route53 nameservers.
2. Update registrar nameservers to Route53 for each domain.
3. Wait for NS propagation.
4. Re-run dig checks without `@<ROUTE53_NS>` to confirm public resolver answers.

## RetroArena stack

Deploy the app hosting stack from:

```bash
cd /Users/paul/git/paulashbourne/infra/services/retroarena
```

See `/Users/paul/git/paulashbourne/infra/services/retroarena/README.md` for full variables, plan/apply steps, and post-apply outputs.
Use that stack for custom app domains such as `retroarena.live`.
