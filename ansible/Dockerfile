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
COPY requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml

# Create non-root user
RUN groupadd --gid 1000 ansible && \
    useradd --uid 1000 --gid ansible --shell /bin/bash --create-home ansible

# Create working directory and set permissions
WORKDIR /ansible
RUN chown -R ansible:ansible /ansible

# Switch to non-root user
USER ansible

# Default command
ENTRYPOINT ["ansible-playbook"]
CMD ["--help"]
