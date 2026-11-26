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

Then re-run `make install-analysis`. After only changing a secret file, run
`make restart-analysis`.

## Supported Secrets

File-based secrets are read by the AI analysis service only.

| Environment Variable | File-based Alternative |
|---------------------|------------------------|
| `ANTHROPIC_API_KEY` | `ANTHROPIC_API_KEY_FILE` |
| `OPENAI_API_KEY` | `OPENAI_API_KEY_FILE` |
| `ANALYSIS_API_TOKEN` | `ANALYSIS_API_TOKEN_FILE` |

The Grafana "Analyze with AI" links get their token from `ANALYSIS_API_TOKEN`
in `.env`, not from `ANALYSIS_API_TOKEN_FILE`. If you use those links, keep the
token in `.env`.

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

## Why File-based Secrets?

1. **Environment**: Secrets don't appear in the container's environment
2. **Integration**: Works with secret managers that write to files (Vault Agent, etc.)
