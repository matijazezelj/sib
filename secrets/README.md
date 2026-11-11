# Secrets Directory

This directory stores file-based secrets for SIB services. Files here are **gitignored** and should never be committed.

## Usage

Instead of putting secrets directly in `.env`:

```bash
# Don't do this in production:
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
```

Store the secret in a file here and point the `_FILE` variable at it. The
analysis container mounts this directory read-only at `/app/secrets`, so use
the container path:

```bash
# In .env:
ANTHROPIC_API_KEY_FILE=/app/secrets/anthropic_api_key

# In secrets/anthropic_api_key (this directory):
sk-ant-api03-xxxxx
```

Then re-run `make install-analysis`.

## Supported Secrets

File-based secrets are read by the AI analysis service only.

| Environment Variable | File-based Alternative |
|---------------------|------------------------|
| `ANTHROPIC_API_KEY` | `ANTHROPIC_API_KEY_FILE` |
| `OPENAI_API_KEY` | `OPENAI_API_KEY_FILE` |
| `ANALYSIS_API_TOKEN` | `ANALYSIS_API_TOKEN_FILE` |

Falcosidekick output credentials (Slack, PagerDuty, AWS, ...) do not support
`_FILE` yet; set them in `.env`.

## Creating Secret Files

```bash
# Create a secret file (ensure no trailing newline)
echo -n "sk-ant-api03-xxxxx" > secrets/anthropic_api_key

# The container runs as a non-root user with a different UID, so the file must
# be readable by "others". Keep other host users out at the directory level:
# 711 lets the container open files by name but not list the directory.
chmod 644 secrets/anthropic_api_key
chmod 711 secrets
```

## Docker Compose Secrets

For production deployments, you can also use Docker Compose secrets:

```yaml
services:
  sib-analysis:
    secrets:
      - anthropic_key
    environment:
      - ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_key

secrets:
  anthropic_key:
    file: ./secrets/anthropic_api_key
```

## Why File-based Secrets?

1. **Process isolation**: Secrets don't appear in `/proc/*/environ`
2. **Logging safety**: Secrets won't leak into debug logs or error messages
3. **Rotation**: Update the file without restarting containers (for some services)
4. **Integration**: Works with secret managers that write to files (Vault Agent, etc.)
