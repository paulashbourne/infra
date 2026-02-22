# paulashbourne infra

Route53 DNS bootstrap for:

- `paulashbourne.com`
- `paulashbourne.ca`

Service stacks:

- `services/n64` for Warpdeck 64 app hosting (`n64.paulashbourne.com`)
- SES sender-domain DNS for Portfolio Pulse email notifications (`portfoliopulse.paulashbourne.com`)

## What this creates

- Two Route53 public hosted zones (one per domain)
- DNS records mirrored from current production DNS to avoid downtime during registrar transfer
- SES domain identity DNS records for `portfoliopulse.paulashbourne.com` (verification + DKIM)

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

## Warpdeck 64 stack

Deploy the app hosting stack from:

```bash
cd /Users/paul/git/paulashbourne/infra/services/n64
```

See `/Users/paul/git/paulashbourne/infra/services/n64/README.md` for full variables, plan/apply steps, and post-apply outputs.
