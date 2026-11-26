# Example Rules and Scenarios

This directory contains example Falco rules and test scenarios for SIB.

## Directory Structure

```
examples/
├── rules/           # Example custom rules
│   ├── aws.yaml     # AWS-specific rules
│   ├── k8s.yaml     # Kubernetes rules
│   └── web.yaml     # Web application rules
└── scenarios/       # Test scenarios
    └── README.md    # How to run scenarios
```

## Quick Demo

Generate sample events (runs `scripts/demo.sh`):
```bash
make demo
```

## Example Rules

| File | Covers |
|------|--------|
| `rules/aws.yaml` | AWS credential access, metadata service, CLI enumeration |
| `rules/web.yaml` | Web shells, uploads, database abuse, reverse shells |
| `rules/k8s.yaml` | Kubernetes audit events. Needs the `k8saudit` plugin, which SIB doesn't configure |

These are examples and are not loaded or checked by SIB. To try one, copy it to
`detection/config/rules/`, add it to `rules_files` (below) and run
`make test-rules`.

## Test Scenarios

Commands that trigger specific rules, with the expected rule names, are in
[scenarios/README.md](scenarios/README.md).

## Adding Your Own Rules

1. Append your rule to `detection/config/rules/custom_rules.yaml`, or create a new YAML file in `detection/config/rules/` and add its path to `rules_files` in `detection/config/falco.yaml.template` (files not listed there are not loaded)
2. Follow the Falco rule format
3. Validate: `make test-rules`
4. Restart Falco (`make restart-detection`; after editing the template, re-run `make install-detection`)

## Rule Writing Tips

1. **Use macros** for reusable conditions
2. **Test incrementally** with lower priorities first
3. **Include context** in output (user, command, container)
4. **Add MITRE tags** for standardized classification
5. **Document** what the rule detects and why
