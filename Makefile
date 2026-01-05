# ==========================================
# SIEM in a Box (SIB) - Main Makefile
# ==========================================
# Usage: make <target>
# Run 'make help' for available commands
# ==========================================

# Colors for output
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
CYAN := \033[36m
RESET := \033[0m
BOLD := \033[1m

# Docker compose command - include root .env file for all stacks
DOCKER_COMPOSE := docker compose --env-file $(CURDIR)/.env

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo ""
	@echo "$(BOLD)🛡️  SIEM in a Box (SIB)$(RESET)"
	@echo ""
	@echo "$(CYAN)Usage:$(RESET)"
	@echo "  make $(GREEN)<target>$(RESET)"
	@echo ""
	@echo "$(CYAN)Installation:$(RESET)"
	@grep -E '^(install|install-detection|install-alerting|install-storage|install-grafana):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Management:$(RESET)"
	@grep -E '^(start|stop|restart|status|uninstall):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Health & Logs:$(RESET)"
	@grep -E '^(health|doctor|logs|logs-falco|logs-sidekick|logs-storage|logs-grafana):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Testing & Demo:$(RESET)"
	@grep -E '^(test-alert|demo|demo-quick|test-rules):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Threat Intel & Sigma:$(RESET)"
	@grep -E '^(update-threatintel|convert-sigma):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Utilities:$(RESET)"
	@grep -E '^(open|open-ui|info|ps|clean|check-ports|validate):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Remote Collectors:$(RESET)"
	@grep -E '^(enable-remote|deploy-collector):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Fleet Management (Ansible):$(RESET)"
	@grep -E '^(fleet-build|deploy-fleet|update-rules|fleet-health|fleet-docker-check|remove-fleet|fleet-ping|fleet-shell):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)Stack-specific commands:$(RESET)"
	@echo "  Commands follow the pattern: $(GREEN)<action>-<stack>$(RESET)"
	@echo "  Example: make install-detection, make stop-alerting, make logs-storage"
	@echo ""

# ==================== Network ====================

network: ## Create shared Docker network
	@docker info >/dev/null 2>&1 || (echo "$(RED)✗ Docker is not running. Please start Docker first.$(RESET)" && exit 1)
	@docker network inspect sib-network >/dev/null 2>&1 || \
		(docker network create sib-network && echo "$(GREEN)✓ Created sib-network$(RESET)")

# ==================== Installation ====================

install: network ## Install all security stacks
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)! No .env file found. Creating from .env.example...$(RESET)"; \
		cp .env.example .env; \
		echo "$(YELLOW)! Please edit .env and set a secure GRAFANA_ADMIN_PASSWORD$(RESET)"; \
		echo ""; \
	fi
	@if grep -q "CHANGE_ME" .env 2>/dev/null; then \
		echo "$(RED)⚠️  WARNING: You're using default passwords!$(RESET)"; \
		echo "$(YELLOW)   Edit .env file and change GRAFANA_ADMIN_PASSWORD$(RESET)"; \
		echo ""; \
	fi
	@$(MAKE) --no-print-directory install-storage
	@$(MAKE) --no-print-directory install-grafana
	@$(MAKE) --no-print-directory install-alerting
	@$(MAKE) --no-print-directory install-detection
	@echo ""
	@echo "$(GREEN)$(BOLD)✓ SIB installation complete!$(RESET)"
	@echo ""
	@echo "$(CYAN)Access points:$(RESET)"
	@echo "  $(BOLD)Grafana:$(RESET)           $(YELLOW)http://localhost:3000$(RESET)"
	@echo "  $(BOLD)Falcosidekick UI:$(RESET)  $(YELLOW)http://localhost:2802$(RESET)"
	@echo "  $(BOLD)Falcosidekick:$(RESET)     $(YELLOW)http://localhost:2801$(RESET)"
	@echo ""
	@echo "$(CYAN)Next steps:$(RESET)"
	@echo "  $(GREEN)make test-alert$(RESET)  Generate a test security alert"
	@echo "  $(GREEN)make open$(RESET)        Open Grafana in browser"
	@echo "  $(GREEN)make health$(RESET)      Verify all services are healthy"
	@echo "  $(GREEN)make info$(RESET)        Show all endpoints and ports"
	@echo ""

install-detection: network ## Install Falco detection stack
	@echo "$(CYAN)🔍 Installing Falco Detection Stack...$(RESET)"
	@cd detection && $(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Detection stack installed$(RESET)"

install-alerting: network ## Install Falcosidekick alerting stack
	@echo "$(CYAN)🔔 Installing Alerting Stack...$(RESET)"
	@cd alerting && $(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Alerting stack installed$(RESET)"

install-storage: network ## Install Loki + Prometheus storage stack
	@echo "$(CYAN)💾 Installing Storage Stack...$(RESET)"
	@cd storage && $(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Storage stack installed$(RESET)"

install-grafana: network ## Install Grafana dashboard
	@echo "$(CYAN)📊 Installing Grafana...$(RESET)"
	@cd grafana && $(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Grafana installed$(RESET)"

# ==================== Start ====================

start: start-storage start-grafana start-alerting start-detection ## Start all stacks
	@echo "$(GREEN)✓ All stacks started$(RESET)"

start-detection: ## Start Falco detection stack
	@cd detection && $(DOCKER_COMPOSE) start

start-alerting: ## Start alerting stack
	@cd alerting && $(DOCKER_COMPOSE) start

start-storage: ## Start storage stack
	@cd storage && $(DOCKER_COMPOSE) start

start-grafana: ## Start Grafana
	@cd grafana && $(DOCKER_COMPOSE) start

# ==================== Stop ====================

stop: stop-detection stop-alerting stop-grafana stop-storage ## Stop all stacks
	@echo "$(GREEN)✓ All stacks stopped$(RESET)"

stop-detection: ## Stop Falco detection stack
	@cd detection && $(DOCKER_COMPOSE) stop

stop-alerting: ## Stop alerting stack
	@cd alerting && $(DOCKER_COMPOSE) stop

stop-storage: ## Stop storage stack
	@cd storage && $(DOCKER_COMPOSE) stop

stop-grafana: ## Stop Grafana
	@cd grafana && $(DOCKER_COMPOSE) stop

# ==================== Restart ====================

restart: restart-storage restart-grafana restart-alerting restart-detection ## Restart all stacks
	@echo "$(GREEN)✓ All stacks restarted$(RESET)"

restart-detection: ## Restart Falco detection stack
	@cd detection && $(DOCKER_COMPOSE) restart

restart-alerting: ## Restart alerting stack
	@cd alerting && $(DOCKER_COMPOSE) restart

restart-storage: ## Restart storage stack
	@cd storage && $(DOCKER_COMPOSE) restart

restart-grafana: ## Restart Grafana
	@cd grafana && $(DOCKER_COMPOSE) restart

# ==================== Uninstall ====================

uninstall: ## Remove all stacks and volumes (with confirmation)
	@echo "$(RED)$(BOLD)⚠️  WARNING: This will delete ALL security data!$(RESET)"
	@echo ""
	@read -p "Are you sure you want to uninstall? [y/N] " confirm && [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ] || (echo "Cancelled." && exit 1)
	@$(MAKE) --no-print-directory uninstall-detection
	@$(MAKE) --no-print-directory uninstall-alerting
	@$(MAKE) --no-print-directory uninstall-grafana
	@$(MAKE) --no-print-directory uninstall-storage
	@docker network rm sib-network 2>/dev/null || true
	@echo "$(GREEN)✓ All stacks removed$(RESET)"

uninstall-detection: ## Remove detection stack and volumes
	@echo "$(YELLOW)Removing detection stack...$(RESET)"
	@cd detection && $(DOCKER_COMPOSE) down -v
	@echo "$(GREEN)✓ Detection stack removed$(RESET)"

uninstall-alerting: ## Remove alerting stack and volumes
	@echo "$(YELLOW)Removing alerting stack...$(RESET)"
	@cd alerting && $(DOCKER_COMPOSE) down -v
	@echo "$(GREEN)✓ Alerting stack removed$(RESET)"

uninstall-storage: ## Remove storage stack and volumes
	@echo "$(YELLOW)Removing storage stack...$(RESET)"
	@cd storage && $(DOCKER_COMPOSE) down -v
	@echo "$(GREEN)✓ Storage stack removed$(RESET)"

uninstall-grafana: ## Remove Grafana and volumes
	@echo "$(YELLOW)Removing Grafana...$(RESET)"
	@cd grafana && $(DOCKER_COMPOSE) down -v
	@echo "$(GREEN)✓ Grafana removed$(RESET)"

# ==================== Status ====================

status: ## Show status of all stacks with health indicators
	@echo ""
	@echo "$(BOLD)🛡️  SIB Stack Status$(RESET)"
	@echo ""
	@printf "  %-22s %-12s %s\n" "SERVICE" "STATUS" "HEALTH"
	@echo "  ────────────────────────────────────────────────────"
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-falco; then \
		health=$$(docker inspect sib-falco --format '{{.State.Health.Status}}' 2>/dev/null || echo "no-healthcheck"); \
		if [ "$$health" = "healthy" ]; then \
			printf "  %-22s $(GREEN)%-12s$(RESET) $(GREEN)✓ healthy$(RESET)\n" "Falco" "running"; \
		else \
			printf "  %-22s $(GREEN)%-12s$(RESET) $(YELLOW)? $$health$(RESET)\n" "Falco" "running"; \
		fi; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Falco" "stopped"; \
	fi
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-sidekick; then \
		health=$$(curl -sf http://localhost:2801/healthz 2>/dev/null && echo "$(GREEN)✓ healthy$(RESET)" || echo "$(YELLOW)? starting$(RESET)"); \
		printf "  %-22s $(GREEN)%-12s$(RESET) %b\n" "Falcosidekick" "running" "$$health"; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Falcosidekick" "stopped"; \
	fi
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-sidekick-ui; then \
		printf "  %-22s $(GREEN)%-12s$(RESET)\n" "Falcosidekick UI" "running"; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Falcosidekick UI" "stopped"; \
	fi
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-loki; then \
		health=$$(curl -sf http://localhost:3100/ready 2>/dev/null && echo "$(GREEN)✓ healthy$(RESET)" || echo "$(YELLOW)? starting$(RESET)"); \
		printf "  %-22s $(GREEN)%-12s$(RESET) %b\n" "Loki" "running" "$$health"; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Loki" "stopped"; \
	fi
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-prometheus; then \
		health=$$(curl -sf http://localhost:9090/-/ready 2>/dev/null && echo "$(GREEN)✓ healthy$(RESET)" || echo "$(YELLOW)? starting$(RESET)"); \
		printf "  %-22s $(GREEN)%-12s$(RESET) %b\n" "Prometheus" "running" "$$health"; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Prometheus" "stopped"; \
	fi
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-grafana; then \
		health=$$(curl -sf http://localhost:3000/api/health 2>/dev/null && echo "$(GREEN)✓ healthy$(RESET)" || echo "$(YELLOW)? starting$(RESET)"); \
		printf "  %-22s $(GREEN)%-12s$(RESET) %b\n" "Grafana" "running" "$$health"; \
	else \
		printf "  %-22s $(RED)%-12s$(RESET)\n" "Grafana" "stopped"; \
	fi
	@echo ""

# ==================== Health ====================

health: ## Quick health check of all services
	@echo ""
	@echo "$(BOLD)🏥 SIB Health Check$(RESET)"
	@echo ""
	@echo "$(CYAN)Detection:$(RESET)"
	@docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-falco && echo "  $(GREEN)✓$(RESET) Falco is running" || echo "  $(RED)✗$(RESET) Falco is not running"
	@echo ""
	@echo "$(CYAN)Alerting:$(RESET)"
	@curl -sf http://localhost:2801/healthz >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Falcosidekick is healthy" || echo "  $(RED)✗$(RESET) Falcosidekick is not responding"
	@docker ps --format '{{.Names}}' 2>/dev/null | grep -q sib-sidekick-ui && echo "  $(GREEN)✓$(RESET) Falcosidekick UI is running" || echo "  $(RED)✗$(RESET) Falcosidekick UI is not running"
	@echo ""
	@echo "$(CYAN)Storage:$(RESET)"
	@curl -sf http://localhost:3100/ready >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Loki is healthy" || echo "  $(RED)✗$(RESET) Loki is not responding"
	@curl -sf http://localhost:9090/-/ready >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Prometheus is healthy" || echo "  $(RED)✗$(RESET) Prometheus is not responding"
	@echo ""
	@echo "$(CYAN)Visualization:$(RESET)"
	@curl -sf http://localhost:3000/api/health >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Grafana is healthy" || echo "  $(RED)✗$(RESET) Grafana is not responding"
	@echo ""

doctor: ## Diagnose common issues
	@echo ""
	@echo "$(BOLD)🩺 SIB Doctor$(RESET)"
	@echo ""
	@echo "$(CYAN)Checking Docker...$(RESET)"
	@docker info >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Docker is running" || echo "  $(RED)✗$(RESET) Docker is not running"
	@docker compose version >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Docker Compose is available" || echo "  $(RED)✗$(RESET) Docker Compose not found"
	@echo ""
	@echo "$(CYAN)Checking configuration...$(RESET)"
	@test -f .env && echo "  $(GREEN)✓$(RESET) .env file exists" || echo "  $(YELLOW)!$(RESET) .env file missing (copy from .env.example)"
	@if [ -f .env ]; then \
		grep -q "CHANGE_ME" .env && echo "  $(YELLOW)!$(RESET) Default password in use - please change" || echo "  $(GREEN)✓$(RESET) Password has been changed"; \
	fi
	@echo ""
	@echo "$(CYAN)Checking network...$(RESET)"
	@docker network inspect sib-network >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) sib-network exists" || echo "  $(YELLOW)!$(RESET) sib-network not created (run 'make network')"
	@echo ""
	@echo "$(CYAN)Checking privileged mode (required for Falco)...$(RESET)"
	@docker run --rm --privileged alpine echo "ok" >/dev/null 2>&1 && echo "  $(GREEN)✓$(RESET) Privileged containers supported" || echo "  $(RED)✗$(RESET) Privileged containers not supported"
	@echo ""
	@echo "$(CYAN)Checking ports...$(RESET)"
	@for port in 2801 2802 3000 3100 9090; do \
		if lsof -Pi :$$port -sTCP:LISTEN -t >/dev/null 2>&1; then \
			echo "  $(GREEN)✓$(RESET) Port $$port is in use (expected if SIB is running)"; \
		else \
			echo "  $(GREEN)✓$(RESET) Port $$port is available"; \
		fi; \
	done
	@echo ""

# ==================== Logs ====================

logs: ## Tail logs from all stacks
	@echo "$(CYAN)Tailing all stack logs (Ctrl+C to stop)...$(RESET)"
	@docker compose -f detection/compose.yaml -f alerting/compose.yaml -f storage/compose.yaml -f grafana/compose.yaml logs -f

logs-falco: ## Tail Falco logs
	@cd detection && $(DOCKER_COMPOSE) logs -f

logs-sidekick: ## Tail Falcosidekick logs
	@cd alerting && $(DOCKER_COMPOSE) logs -f sidekick

logs-storage: ## Tail storage stack logs (Loki + Prometheus)
	@cd storage && $(DOCKER_COMPOSE) logs -f

logs-grafana: ## Tail Grafana logs
	@cd grafana && $(DOCKER_COMPOSE) logs -f

# ==================== Testing ====================

test-alert: ## Generate a test security alert
	@echo ""
	@echo "$(BOLD)🧪 Generating Test Alert$(RESET)"
	@echo ""
	@echo "$(CYAN)Sending test event to Falcosidekick...$(RESET)"
	@curl -sf -X POST -H "Content-Type: application/json" -H "Accept: application/json" \
		http://localhost:2801/test 2>/dev/null && \
		echo "$(GREEN)✓ Test alert sent successfully!$(RESET)" || \
		echo "$(RED)✗ Failed to send test alert. Is Falcosidekick running?$(RESET)"
	@echo ""
	@echo "$(CYAN)Check the alert in:$(RESET)"
	@echo "  • Falcosidekick UI: $(YELLOW)http://localhost:2802$(RESET)"
	@echo "  • Grafana:          $(YELLOW)http://localhost:3000$(RESET)"
	@echo ""

demo: ## Run comprehensive security demo (generates ~30 events)
	@./scripts/demo.sh

demo-quick: ## Run quick security demo (1s delay between events)
	@./scripts/demo.sh --quick

test-rules: ## Validate Falco rules syntax
	@echo "$(CYAN)Validating Falco rules...$(RESET)"
	@docker run --rm -v $(PWD)/detection/config:/etc/falco:ro \
		falcosecurity/falco:latest \
		falco --validate /etc/falco/rules/ 2>&1 | head -20 || true
	@echo ""

# ==================== Threat Intel & Sigma ====================

update-threatintel: ## Download/update threat intelligence feeds
	@./threatintel/update-feeds.sh

convert-sigma: ## Convert Sigma rules to Falco format
	@echo "$(CYAN)Converting Sigma rules...$(RESET)"
	@python3 ./sigma/sigma2sib.py ./sigma/rules/ -o falco
	@echo ""
	@echo "$(GREEN)✓ Converted rules saved to sigma/rules/converted_falco_rules.yaml$(RESET)"
	@echo "$(CYAN)Copy to Falco with:$(RESET)"
	@echo "  $(YELLOW)cp sigma/rules/converted_falco_rules.yaml detection/config/rules/$(RESET)"

# ==================== Utilities ====================

open: ## Open Grafana in browser
	@echo "$(CYAN)Opening Grafana...$(RESET)"
	@open http://localhost:3000 2>/dev/null || xdg-open http://localhost:3000 2>/dev/null || echo "Open http://localhost:3000 in your browser"

open-ui: ## Open Falcosidekick UI in browser
	@echo "$(CYAN)Opening Falcosidekick UI...$(RESET)"
	@open http://localhost:2802 2>/dev/null || xdg-open http://localhost:2802 2>/dev/null || echo "Open http://localhost:2802 in your browser"

info: ## Show all endpoints and ports
	@echo ""
	@echo "$(BOLD)📡 SIB Endpoints$(RESET)"
	@echo ""
	@echo "$(CYAN)Web Interfaces:$(RESET)"
	@echo "  Grafana:            $(YELLOW)http://localhost:3000$(RESET)"
	@echo "  Falcosidekick UI:   $(YELLOW)http://localhost:2802$(RESET)"
	@echo ""
	@echo "$(CYAN)APIs:$(RESET)"
	@echo "  Falcosidekick:      $(YELLOW)http://localhost:2801$(RESET)"
	@echo "  Loki:               $(YELLOW)http://localhost:3100$(RESET)"
	@echo "  Prometheus:         $(YELLOW)http://localhost:9090$(RESET)"
	@echo ""
	@echo "$(CYAN)Internal (sib-network):$(RESET)"
	@echo "  Falcosidekick:      sib-sidekick:2801"
	@echo "  Loki:               sib-loki:3100"
	@echo "  Prometheus:         sib-prometheus:9090"
	@echo ""

ps: ## Show running SIB containers
	@echo ""
	@docker ps --filter "network=sib-network" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""

check-ports: ## Check if required ports are available
	@echo ""
	@echo "$(BOLD)🔌 Port Check$(RESET)"
	@echo ""
	@for port in 2801 2802 3000 3100 9090; do \
		if lsof -Pi :$$port -sTCP:LISTEN -t >/dev/null 2>&1; then \
			proc=$$(lsof -Pi :$$port -sTCP:LISTEN -t 2>/dev/null | head -1); \
			echo "  $(YELLOW)!$(RESET) Port $$port is in use (PID: $$proc)"; \
		else \
			echo "  $(GREEN)✓$(RESET) Port $$port is available"; \
		fi; \
	done
	@echo ""

validate: ## Validate all configuration files
	@echo ""
	@echo "$(BOLD)🔍 Validating configurations...$(RESET)"
	@echo ""
	@echo "$(CYAN)Docker Compose files:$(RESET)"
	@for dir in detection alerting storage grafana; do \
		if [ -f "$$dir/compose.yaml" ]; then \
			cd $$dir && $(DOCKER_COMPOSE) config --quiet 2>/dev/null && echo "  $(GREEN)✓$(RESET) $$dir/compose.yaml" || echo "  $(RED)✗$(RESET) $$dir/compose.yaml has errors"; \
			cd ..; \
		fi; \
	done
	@echo ""
	@echo "$(CYAN)YAML syntax:$(RESET)"
	@for file in storage/config/loki-config.yml storage/config/prometheus.yml; do \
		if [ -f "$$file" ]; then \
			docker run --rm -v "$(PWD)/$$file:/file.yml:ro" mikefarah/yq '.' /file.yml >/dev/null 2>&1 && \
			echo "  $(GREEN)✓$(RESET) $$file" || echo "  $(RED)✗$(RESET) $$file has syntax errors"; \
		fi; \
	done
	@echo ""

clean: ## Remove unused Docker resources
	@echo "$(CYAN)Cleaning up unused Docker resources...$(RESET)"
	@docker system prune -f
	@echo "$(GREEN)✓ Cleanup complete$(RESET)"

# ==================== Update ====================

update: ## Pull latest images and restart all stacks
	@echo "$(CYAN)Pulling latest images...$(RESET)"
	@cd detection && $(DOCKER_COMPOSE) pull
	@cd alerting && $(DOCKER_COMPOSE) pull
	@cd storage && $(DOCKER_COMPOSE) pull
	@cd grafana && $(DOCKER_COMPOSE) pull
	@echo ""
	@echo "$(CYAN)Restarting stacks with new images...$(RESET)"
	@$(MAKE) --no-print-directory restart
	@echo ""
	@echo "$(GREEN)✓ All stacks updated$(RESET)"

.PHONY: help network install install-detection install-alerting install-storage install-grafana \
        start start-detection start-alerting start-storage start-grafana \
        stop stop-detection stop-alerting stop-storage stop-grafana \
        restart restart-detection restart-alerting restart-storage restart-grafana \
        uninstall uninstall-detection uninstall-alerting uninstall-storage uninstall-grafana \
        status health doctor logs logs-falco logs-sidekick logs-storage logs-grafana \
        test-alert demo test-rules open open-ui info ps check-ports validate clean update \
        enable-remote deploy-collector

# ==================== Remote Collectors ====================

enable-remote: ## Enable remote connections from Alloy collectors
	@echo "$(CYAN)🌐 Enabling remote connections for collectors...$(RESET)"
	@echo ""
	@echo "$(YELLOW)This will expose Loki (3100) and Prometheus (9090) externally.$(RESET)"
	@echo "$(YELLOW)Make sure your firewall is configured appropriately.$(RESET)"
	@echo ""
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@if grep -q "^STORAGE_BIND=" .env 2>/dev/null; then \
		sed -i.bak 's/^STORAGE_BIND=.*/STORAGE_BIND=0.0.0.0/' .env && rm -f .env.bak; \
	else \
		echo "STORAGE_BIND=0.0.0.0" >> .env; \
	fi
	@cd storage && $(DOCKER_COMPOSE) up -d
	@echo ""
	@echo "$(GREEN)✓ Remote connections enabled$(RESET)"
	@echo ""
	@echo "$(CYAN)Collectors can now send data to:$(RESET)"
	@echo "  Loki:       http://$$(hostname -I 2>/dev/null | awk '{print $$1}' || echo 'YOUR_IP'):3100"
	@echo "  Prometheus: http://$$(hostname -I 2>/dev/null | awk '{print $$1}' || echo 'YOUR_IP'):9090"
	@echo ""
	@echo "$(CYAN)Deploy a collector with:$(RESET)"
	@echo "  make deploy-collector HOST=user@remote-host"
	@echo ""

deploy-collector: ## Deploy Alloy collector to remote host (HOST=user@host)
	@if [ -z "$(HOST)" ]; then \
		echo "$(RED)✗ Please specify HOST=user@remote-host$(RESET)"; \
		echo "  Example: make deploy-collector HOST=ubuntu@192.168.1.50"; \
		exit 1; \
	fi
	@SIB_IP=$$(hostname -I 2>/dev/null | awk '{print $$1}'); \
	if [ -z "$$SIB_IP" ]; then \
		read -p "Enter SIB server IP: " SIB_IP; \
	fi; \
	chmod +x collectors/scripts/deploy.sh && \
	./collectors/scripts/deploy.sh $(HOST) $$SIB_IP

# ==================== Fleet Management (Ansible) ====================

# Ansible runs in Docker - no local installation needed
ANSIBLE_IMAGE := sib-ansible:latest
ANSIBLE_RUN := docker compose -f ansible/compose.yaml run --rm ansible
LIMIT := $(if $(LIMIT),--limit $(LIMIT),)
ARGS := $(if $(ARGS),$(ARGS),)

fleet-build: ## Build Ansible Docker image for fleet management
	@echo "$(CYAN)🔨 Building Ansible container...$(RESET)"
	@docker compose -f ansible/compose.yaml build
	@echo "$(GREEN)✓ Ansible container ready$(RESET)"

deploy-fleet: ## Deploy Falco + Alloy to fleet hosts (LIMIT=host to target specific)
	@if [ ! -f ansible/inventory/hosts.yml ]; then \
		echo "$(RED)✗ No inventory found at ansible/inventory/hosts.yml$(RESET)"; \
		echo "$(YELLOW)  Copy the example: cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml$(RESET)"; \
		echo "$(YELLOW)  Then edit it with your hosts.$(RESET)"; \
		exit 1; \
	fi
	@docker compose -f ansible/compose.yaml build -q 2>/dev/null || true
	@echo "$(CYAN)🚀 Deploying SIB agents to fleet...$(RESET)"
	@$(ANSIBLE_RUN) -i inventory/hosts.yml playbooks/deploy-fleet.yml $(LIMIT) $(ARGS)
	@echo ""
	@echo "$(GREEN)✓ Fleet deployment complete$(RESET)"

update-rules: ## Push updated Falco rules to fleet hosts
	@echo "$(CYAN)📤 Pushing rules to fleet...$(RESET)"
	@$(ANSIBLE_RUN) -i inventory/hosts.yml playbooks/update-rules.yml $(LIMIT) $(ARGS)

fleet-health: ## Check health of all fleet agents
	@echo "$(CYAN)🏥 Checking fleet health...$(RESET)"
	@$(ANSIBLE_RUN) -i inventory/hosts.yml playbooks/health-check.yml $(LIMIT) $(ARGS)

fleet-docker-check: ## Check Docker on fleet, install if missing (ARGS="-e auto_install=false" for check only)
	@echo "$(CYAN)🐳 Checking Docker on fleet...$(RESET)"
	@$(ANSIBLE_RUN) -i inventory/hosts.yml playbooks/docker-check.yml $(LIMIT) $(ARGS)

remove-fleet: ## Remove SIB agents from fleet (requires confirmation)
	@echo "$(YELLOW)⚠️  This will remove SIB agents from fleet hosts$(RESET)"
	@$(ANSIBLE_RUN) -i inventory/hosts.yml playbooks/remove-fleet.yml $(LIMIT) -e confirm_removal=true $(ARGS)

fleet-shell: ## Open shell in Ansible container for manual commands
	@docker compose -f ansible/compose.yaml run --rm --entrypoint /bin/bash ansible

fleet-ping: ## Test SSH connectivity to all fleet hosts
	@docker compose -f ansible/compose.yaml run --rm --entrypoint ansible ansible \
		-i inventory/hosts.yml fleet -m ping
