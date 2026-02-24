# Contributing to SIB (SIEM in a Box)

Thank you for your interest in contributing to SIB! This document provides guidelines for contributing.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sib.git
   cd sib
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Start the development stack:
   ```bash
   make install
   ```

3. Run health checks:
   ```bash
   make health
   make doctor
   ```

## Project Structure

```
sib/
├── alerting/       # Falcosidekick configuration
├── analysis/       # AI-powered analysis API
├── ansible/        # Fleet deployment automation
├── certs/          # mTLS certificates (generated)
├── collectors/     # Remote host collectors (Vector/vmagent or Alloy)
├── detection/      # Falco rules and configuration
├── docs/           # Documentation
├── grafana/        # Dashboards and visualization
├── scripts/        # Helper scripts
├── sigma/          # Sigma rule conversion
├── storage/        # VictoriaLogs/VictoriaMetrics or Loki/Prometheus
└── threatintel/    # Threat intelligence feeds
```

> **Note:** Some config files are **generated** by `make install` and listed in `.gitignore`:
> `detection/config/falco.yaml`, `alerting/config/config.yaml`, `grafana/provisioning/datasources/datasources.yml`

## Types of Contributions

### Adding Falco Rules

1. Add rules to `detection/config/rules/custom_rules.yaml`
2. Test with: `make test-rules`
3. Generate test alerts: `make demo`

### Improving Dashboards

1. Edit dashboards in Grafana UI
2. Export JSON via Grafana's share → export
3. Save to `grafana/provisioning/dashboards/json/`

### Adding Sigma Rule Conversions

1. Add Sigma rules to `sigma/rules/`
2. Convert: `make convert-sigma`
3. Review the generated Falco rules

### Improving Documentation

- README.md - Main documentation
- docs/index.md - GitHub Pages site
- Component READMEs in each directory

## Code Style

- **YAML**: 2-space indentation
- **Python**: Follow PEP 8, use type hints
- **Shell Scripts**: Use shellcheck, quote variables
- **Makefile**: Include help comments (`## description`)

## Testing

Before submitting a PR:

1. Validate configurations:
   ```bash
   make validate
   ```

2. Run the full stack:
   ```bash
   make install
   make health
   ```

3. Generate test alerts:
   ```bash
   make test-alert
   make demo
   ```

## Pull Request Process

1. Update documentation if needed
2. Ensure `make validate` passes
3. Test with `make install && make health`
4. Write a clear PR description
5. Reference any related issues

## Reporting Bugs

Please include:
- Operating system and version
- Docker/Podman version
- Output of `make doctor`
- Steps to reproduce
- Expected vs actual behavior

## Feature Requests

Open an issue with:
- Clear description of the feature
- Use case and benefits
- Potential implementation approach

## Questions?

Open a GitHub issue with the `question` label.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
