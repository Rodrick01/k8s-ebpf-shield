CLUSTER_NAME := ebpf-shield-cluster

.PHONY: all
all: deploy

.PHONY: deploy
deploy:
	@echo "=> Inicializando Terraform..."
	@cd terraform && terraform init
	@echo "=> Desplegando Infraestructura (K8s) y Telemetría..."
	@cd terraform && terraform apply -auto-approve

.PHONY: clean
clean:
	@echo "=> Destruyendo Infraestructura con Terraform..."
	@cd terraform && terraform destroy -auto-approve
	@echo "=> Infraestructura eliminada."

.PHONY: status
status:
	@kubectl get nodes -o wide
	@echo ""
	@kubectl get pods -A -o wide
