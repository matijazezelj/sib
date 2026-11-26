# SIB mTLS Certificates

This directory contains certificates for mTLS (mutual TLS) communication between SIB components.

## Directory Structure

```
certs/
├── ca/                     # Certificate Authority
│   ├── ca.crt             # CA certificate (public - safe to distribute)
│   └── ca.key             # CA private key (SECRET - protect this!)
├── server/                 # Server certificate (for Falcosidekick)
│   ├── server.crt         # Server certificate
│   ├── server.key         # Server private key
│   └── server.cnf         # OpenSSL config with SANs
├── clients/                # Client certificates (one per fleet host)
│   ├── local.crt          # Local SIB server's Falco client cert
│   ├── local.key          # Local client private key
│   ├── fleet-host-1.crt   # Fleet host certificates...
│   ├── fleet-host-1.key
│   └── metrics-scraper.crt/.key  # Created by make install-storage-* when MTLS_ENABLED=true
└── README.md              # This file
```

## Quick Start

Generate all certificates (CA, server, local client):

```bash
make generate-certs
```

Generate certificate for a specific fleet host:

```bash
make generate-client-cert HOST=my-fleet-host
```

Generate certificates for all hosts in Ansible inventory:

```bash
make generate-fleet-certs
```

Creating certificates doesn't enable mTLS. Set `MTLS_ENABLED=true` in `.env`
and reinstall (Falco then talks to Sidekick over https); see
[Security Hardening](../docs/security-hardening.md#5-enable-mtls-for-fleet-communication).

The server certificate covers localhost, SIB's container names and the host's
detected IPv4 addresses (not `172.*`). Set `SIB_SERVER_IP` or `SERVER_CN` (a DNS
name) when running `make generate-certs` if fleet hosts use another address.

The server key is group-readable (`0640`). Falcosidekick reads it through
`SIDECAR_CONFIG_GID`, so that must be the key file's group.

## Security Notes

- **NEVER commit private keys (*.key files) to version control**
- The `.gitignore` is configured to exclude sensitive files
- Store CA private key (`ca/ca.key`) securely - it can sign any certificate
- Rotate certificates before expiration (default: 1 year for certs, 5 years for CA)
- Use strong passphrases if you encrypt the CA key

## Certificate Validity

| Certificate | Default Validity | Environment Variable |
|-------------|------------------|---------------------|
| CA          | 5 years (1825 days) | `CA_VALIDITY_DAYS` |
| Server      | 1 year (365 days) | `CERT_VALIDITY_DAYS` |
| Client      | 1 year (365 days) | `CERT_VALIDITY_DAYS` |

## Verification

Verify all certificates:

```bash
make verify-certs
```

Or manually verify a certificate:

```bash
# Verify server cert against CA
openssl verify -CAfile certs/ca/ca.crt certs/server/server.crt

# View certificate details
openssl x509 -in certs/server/server.crt -text -noout

# Check certificate expiration
openssl x509 -in certs/server/server.crt -noout -dates
```

## Regenerating Certificates

If you need to regenerate certificates (e.g., CA compromise, expiration):

1. **Regenerate CA** (invalidates ALL existing certs). `make rotate-certs`
   renews the CA, the server certificate, the `local` client certificate and
   the fleet certificates (answer `y` to both prompts; it needs an Ansible
   inventory). The `metrics-scraper` certificate is reissued by the next
   storage install, which notices it no longer matches the CA:
   ```bash
   make rotate-certs
   make install-storage-vm   # or install-storage-grafana
   make restart-alerting restart-detection
   make deploy-fleet
   ```

2. **Regenerate server cert only**:
   ```bash
   ./scripts/generate-certs.sh server
   make restart-alerting
   ```

3. **Regenerate single client cert**:
   ```bash
   ./scripts/generate-client-cert.sh hostname
   make deploy-fleet LIMIT=hostname
   ```

## Troubleshooting

### Certificate verification failed
```bash
# Check if cert was signed by CA
openssl verify -CAfile certs/ca/ca.crt certs/clients/hostname.crt
```

### Connection refused with TLS
```bash
# Test TLS connection
openssl s_client -connect localhost:2801 -CAfile certs/ca/ca.crt \
    -cert certs/clients/local.crt -key certs/clients/local.key
```

### Check server certificate SANs
```bash
openssl x509 -in certs/server/server.crt -noout -text | grep -A1 "Subject Alternative Name"
```
