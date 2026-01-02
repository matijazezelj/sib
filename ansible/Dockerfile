FROM python:3.11-slim

LABEL maintainer="SIB - SIEM in a Box"
LABEL description="Ansible control container for SIB fleet management"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Ansible and required collections
RUN pip install --no-cache-dir \
    ansible \
    ansible-lint \
    jmespath

# Install Ansible collections
RUN ansible-galaxy collection install \
    ansible.posix \
    community.docker \
    community.general

# Create working directory
WORKDIR /ansible

# Default command
ENTRYPOINT ["ansible-playbook"]
CMD ["--help"]
