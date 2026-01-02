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

Run all example scenarios:
```bash
make demo
```

## Example Rules

### AWS Rules
Detect AWS credential abuse:
```yaml
- rule: AWS Credentials in Environment
  desc: Detect AWS credentials in environment variables
  condition: >
    spawned_process and
    (proc.env contains "AWS_ACCESS_KEY" or
     proc.env contains "AWS_SECRET")
  output: "AWS creds in env (cmd=%proc.cmdline)"
  priority: WARNING
```

### Kubernetes Rules
Detect K8s misconfigurations:
```yaml
- rule: Privileged Pod Created
  desc: Detect creation of privileged pod
  condition: >
    kevt and
    k8s.pod.privileged=true
  output: "Privileged pod (pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: WARNING
```

### Web Application Rules
Detect common web attacks:
```yaml
- rule: SQL Injection Attempt
  desc: Detect SQL injection patterns
  condition: >
    inbound and
    fd.rip != "127.0.0.1" and
    (evt.buffer contains "UNION SELECT" or
     evt.buffer contains "1=1")
  output: "SQL injection attempt (src=%fd.cip)"
  priority: WARNING
```

## Test Scenarios

### 1. Container Shell
Spawn a shell in a container:
```bash
docker run --rm alpine sh -c "echo test"
```

### 2. Sensitive File Access
Access shadow file:
```bash
docker run --rm alpine cat /etc/shadow
```

### 3. Network Tool
Use netcat in container:
```bash
docker run --rm alpine nc -v google.com 80
```

### 4. Package Installation
Install package in container:
```bash
docker run --rm alpine apk add curl
```

## Adding Your Own Rules

1. Create a YAML file in `detection/config/rules/`
2. Follow the Falco rule format
3. Restart Falco: `make restart-detection`
4. Validate: `make test-rules`

## Rule Writing Tips

1. **Use macros** for reusable conditions
2. **Test incrementally** with lower priorities first
3. **Include context** in output (user, command, container)
4. **Add MITRE tags** for standardized classification
5. **Document** what the rule detects and why
