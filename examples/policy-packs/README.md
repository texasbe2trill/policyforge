# Policy Packs

Ready-to-use policy configurations for common scenarios. Copy one into `configs/` and point PolicyForge at it:

```bash
cp examples/policy-packs/pci-demo.yaml configs/policy.yaml
go run ./cmd/policyforge --policy configs/policy.yaml --drift-check
```

## Included Packs

| Pack | Use Case |
|---|---|
| [pci-demo.yaml](pci-demo.yaml) | PCI-DSS-aligned environment with strict prod controls |
| [prod-sre.yaml](prod-sre.yaml) | SRE team managing production with tiered escalation |
| [ci-agent.yaml](ci-agent.yaml) | CI/CD pipeline agents with narrow, time-boxed permissions |
| [breakglass-admin.yaml](breakglass-admin.yaml) | Emergency access with mandatory approval on every action |

## Customizing

Each pack is self-contained. To adapt one:

1. Copy it to `configs/`
2. Add or remove roles, resources, and agent envelopes
3. Adjust `requires_approval` on resources and tiers to match your risk model
4. Run `go run ./cmd/policyforge --policy configs/your-policy.yaml --drift-check` to validate

See the main [README](../../README.md) for full policy configuration reference.
