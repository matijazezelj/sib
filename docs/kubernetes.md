---
layout: default
title: Kubernetes
nav_order: 8
---

# Kubernetes Security Monitoring

Kubernetes environments are handled by a dedicated project: **[sib-k8s](https://github.com/matijazezelj/sib-k8s)** — a single Helm chart that deploys the full SIB stack inside a Kubernetes cluster.

## Why a separate chart?

The main SIB stack is built around Docker Compose and targets Linux hosts. Kubernetes needs a different approach:

- **Falco runs as a DaemonSet** — one pod per node, not a sidecar
- **Audit log collection** — K8s API server events (secret access, RBAC changes, privileged pods) come from the cloud provider's audit pipeline, not from syscalls
- **Helm is the native packaging format** — ConfigMaps for rules, PVCs for storage, Services for discovery

Rather than bolt Kubernetes support onto Docker Compose, sib-k8s is a purpose-built Helm chart that deploys and wires all components automatically.

## What sib-k8s includes

```
K8s Audit API (EKS / GKE / AKS / webhook)
          ↓
    Falco (DaemonSet)
          ↓
  Falcosidekick (routing)
      ↙         ↘
    Loki       Analyzer
   (logs)    (AI + obfuscation)
      ↘           ↓
       Grafana (dashboards)
```

| Component | Role |
|-----------|------|
| Falco DaemonSet | Syscall monitoring on every node |
| k8saudit plugin | K8s API audit log collection |
| Falcosidekick | Routes alerts to Loki and the analyzer |
| Loki | Log storage |
| Grafana | Dashboards |
| Analyzer | FastAPI service — real-time AI analysis via Falcosidekick webhook |

## Supported environments

| Platform | Audit source |
|----------|-------------|
| Generic Kubernetes | API server webhook |
| AWS EKS | CloudWatch Logs (k8saudit-eks plugin) |
| Google GKE | Cloud Logging (k8saudit-gke plugin) |
| Azure AKS | Event Hub (k8saudit-aks plugin) |

## Quick start

```bash
git clone https://github.com/matijazezelj/sib-k8s.git
cd sib-k8s
helm dependency update

# Generic Kubernetes
helm install sib-k8s . -f values-k8saudit.yaml -n sib-k8s --create-namespace

# AWS EKS
helm install sib-k8s . -f values-eks.yaml -n sib-k8s --create-namespace

# Google GKE
helm install sib-k8s . -f values-gke.yaml -n sib-k8s --create-namespace

# Azure AKS
helm install sib-k8s . -f values-aks.yaml -n sib-k8s --create-namespace
```

## Relationship to main SIB

The two projects are **complementary**, not alternatives:

| | SIB (this repo) | sib-k8s |
|---|---|---|
| Target | Linux hosts, VMs, bare metal | Kubernetes clusters |
| Deployment | Docker Compose + Ansible fleet | Helm chart |
| Audit source | Falco syscall eBPF | Falco syscall + K8s audit API |
| Alert analyzer | Flask API, analysis on demand | FastAPI, real-time webhook |

A typical setup runs both: **SIB on the underlying nodes** (or your non-K8s servers), **sib-k8s inside the cluster**. The two Grafana instances operate independently — or you can point sib-k8s at an external Loki/VictoriaLogs instance if you want a single pane of glass.

## Detection coverage

sib-k8s ships rules from the Falco k8saudit plugin covering:

- Privileged and sensitive container launches
- Kubernetes secret and configmap access
- RBAC changes (role and rolebinding modifications)
- Cluster admin binding attempts
- NodePort service creation
- Non-system user API access
- GKE-specific allowlist overrides

For syscall-level detection inside pods (shell spawns, credential file reads, network sniffing), Falco's standard runtime rules apply on every node via the DaemonSet.

## Links

- **Repository**: [github.com/matijazezelj/sib-k8s](https://github.com/matijazezelj/sib-k8s)
- **Falco k8saudit plugin**: [github.com/falcosecurity/plugins](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit)
- **Falco K8s docs**: [falco.org/docs/concepts/data-source/kubernetes](https://falco.org/docs/concepts/data-source/kubernetes/)
