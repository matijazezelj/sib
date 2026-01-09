# Test Scenarios

This directory contains test scenarios to validate SIB detection capabilities.

## Quick Test

Generate a test alert via Falcosidekick:
```bash
make test-alert
```

## Container Security Scenarios

### 1. Shell in Container
```bash
# This should trigger: "Terminal shell in container"
docker run --rm -it alpine sh
```

### 2. Sensitive File Access
```bash
# This should trigger: "Read sensitive file"
docker run --rm alpine cat /etc/shadow
```

### 3. Package Installation
```bash
# This should trigger: "Package management in container"
docker run --rm alpine apk add curl
```

### 4. Network Tool Usage
```bash
# This should trigger: "Network tool usage"
docker run --rm alpine sh -c "apk add --no-cache netcat-openbsd && nc -v google.com 80"
```

## Privilege Escalation Scenarios

### 5. Privileged Container
```bash
# This may trigger container escape warnings
docker run --rm --privileged alpine whoami
```

### 6. Host Filesystem Mount
```bash
# Mounting host filesystem
docker run --rm -v /etc:/host-etc alpine cat /host-etc/passwd
```

## Credential Access Scenarios

### 7. SSH Key Access
```bash
# This should trigger: "SSH private key accessed"
docker run --rm -v ~/.ssh:/root/.ssh:ro alpine cat /root/.ssh/id_rsa 2>/dev/null || echo "No key"
```

### 8. AWS Credentials
```bash
# This should trigger: "AWS credentials file accessed"
docker run --rm -v ~/.aws:/root/.aws:ro alpine cat /root/.aws/credentials 2>/dev/null || echo "No creds"
```

## Persistence Scenarios

### 9. Crontab Modification
```bash
# This should trigger: "Crontab modified"
docker run --rm alpine sh -c "echo '* * * * * echo test' >> /etc/crontabs/root"
```

## Network Scenarios

### 10. Suspicious Outbound Connection
```bash
# Connect to suspicious port
docker run --rm alpine sh -c "apk add --no-cache netcat-openbsd && nc -v 1.1.1.1 4444" 2>/dev/null || true
```

## Running All Scenarios

Run the full demo:
```bash
make demo
```

## Viewing Results

After running scenarios:

1. **Grafana**: http://localhost:3000 → Security Overview dashboard
2. **Logs**: `make logs-falco`

## Expected Events

| Scenario | Expected Rule | Priority |
|----------|--------------|----------|
| Shell in container | Terminal shell in container | NOTICE |
| Shadow file access | Read sensitive file untrusted | WARNING |
| Package install | Package management process | NOTICE |
| Privileged container | Container running as root | NOTICE |
| SSH key access | SSH private key accessed | WARNING |
| Crontab modification | Crontab modified | WARNING |

## Troubleshooting

If events don't appear:

1. Check Falco is running: `docker ps | grep falco`
2. Check Falco logs: `make logs-falco`
3. Verify Falcosidekick: `curl http://localhost:2801/healthz`
4. Check Loki: `curl http://localhost:3100/ready`
