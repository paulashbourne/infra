# paulashbourne infra

Route53 DNS bootstrap for:

- `paulashbourne.com`
- `paulashbourne.ca`

## What this creates

- Two Route53 public hosted zones (one per domain)
- DNS records mirrored from current production DNS to avoid downtime during registrar transfer

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
