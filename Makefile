# Idempotent Makefile for K8s HA Cluster + eBPF Shield
CLUSTER_NAME := ebpf-shield-cluster

.PHONY: all
all: cluster deploy

.PHONY: cluster
cluster:
	@echo "=> Checking if Kind cluster '$(CLUSTER_NAME)' exists..."
	@if kind get clusters | grep -q "^$(CLUSTER_NAME)$$"; then \
		echo "=> Cluster '$(CLUSTER_NAME)' already exists. Ensuring idempotency by taking no action."; \
	else \
		echo "=> Creating highly-available 3-node Kind cluster..."; \
		kind create cluster --name $(CLUSTER_NAME) --config infrastructure/kind-config.yaml; \
	fi

.PHONY: deploy
deploy:
	@echo "=> Deploying Normie HA Workload (NGINX)..."
	@kubectl apply -f manifests/app/
	@echo "=> Deploying eBPF Shield DaemonSet..."
	@kubectl apply -f manifests/security/

.PHONY: clean
clean:
	@echo "=> Destroying cluster if it exists..."
	@if kind get clusters | grep -q "^$(CLUSTER_NAME)$$"; then \
		kind delete cluster --name $(CLUSTER_NAME); \
		echo "=> Cluster destroyed successfully."; \
	else \
		echo "=> Cluster does not exist. Nothing to do."; \
	fi

.PHONY: status
status:
	@kubectl get nodes -o wide
	@echo ""
	@kubectl get pods -A -o wide
