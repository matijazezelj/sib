# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in SIB, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to the maintainers privately
3. Provide:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Security Considerations

### Container Privileges

SIB uses privileged containers for Falco syscall monitoring. This is required for security monitoring but has implications:

- **Falco container** runs with `--privileged` to access kernel syscalls
- **Podman users** must run in rootful mode (`sudo podman`)
- Only run on trusted hosts

### Network Security

Default configuration:
- Services bind to `127.0.0.1` (localhost only)
- Use `make enable-remote` to expose services

Recommendations:
- Use firewall rules to restrict access
- Use VPN or private network for remote collectors
- Enable mTLS for production fleet deployments

### mTLS (Mutual TLS)

SIB supports mTLS for encrypted, authenticated communication between components:

**Components secured by mTLS (when enabled):**
- **Falco → Falcosidekick**: Falco sends alerts over HTTPS with client certificate authentication
- **Fleet agents → Falcosidekick**: Remote Falco instances authenticate with client certs

**Enable mTLS:**
```bash
# Generate certificates
make generate-certs

# Enable mTLS
echo "MTLS_ENABLED=true" >> .env

# Reinstall to apply
make install
```

**For fleet deployments:**
```bash
# Generate client certs for each host
make generate-client-cert HOST=hostname

# Deploy via Ansible with mtls_enabled: true
```

See [Security Hardening](docs/security-hardening.md) for complete mTLS documentation.

### API Keys

For AI Analysis:
- Store API keys in `.env` file (never commit)
- `.env` is in `.gitignore`
- Use environment variables in production

### Data Privacy

The AI Analysis feature:
- Obfuscates sensitive data before LLM analysis
- Supports Ollama for fully local, private analysis
- Configure obfuscation level in `analysis/config.yaml`

## Security Best Practices

1. **Grafana password is auto-generated**
   ```bash
   # View your generated password
   grep GRAFANA_ADMIN_PASSWORD .env
   ```

2. **Keep images updated**
   ```bash
   make update
   ```

3. **Review Falco rules**
   ```bash
   make test-rules
   ```

4. **Monitor SIB health**
   ```bash
   make health
   make doctor
   ```

5. **Restrict network access**
   - Keep `STORAGE_BIND=127.0.0.1` unless needed
   - Use firewall rules for remote access

## Known Limitations

- Falco requires kernel access, which needs privileged mode
- mTLS is optional but recommended for production (disabled by default)
- Storage backends (Loki/VictoriaLogs) rely on network isolation (localhost binding)

## Security Updates

Monitor:
- [Falco Security Advisories](https://github.com/falcosecurity/falco/security/advisories)
- [Grafana Security Advisories](https://grafana.com/docs/grafana/latest/release-notes/)
- [Loki Security](https://grafana.com/docs/loki/latest/)
