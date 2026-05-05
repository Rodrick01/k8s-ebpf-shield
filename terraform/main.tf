terraform {
  required_providers {
    kind = {
      source  = "tehcyx/kind"
      version = "~> 0.4.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24.0"
    }
  }
}

provider "kind" {}

# Creación Idempotente del Clúster de 3 Nodos (IaC)
resource "kind_cluster" "default" {
  name           = "ebpf-shield-cluster"
  node_image     = "kindest/node:v1.29.2"
  wait_for_ready = true

  kind_config {
      kind        = "Cluster"
      api_version = "kind.x-k8s.io/v1alpha4"
      
      node {
          role = "control-plane"
      }
      node {
          role = "worker"
      }
      node {
          role = "worker"
      }
      node {
          role = "worker"
      }
  }
}

# Configuración dinámica del provider de K8s conectándose al cluster recién creado
provider "kubernetes" {
  host                   = kind_cluster.default.endpoint
  client_certificate     = kind_cluster.default.client_certificate
  client_key             = kind_cluster.default.client_key
  cluster_ca_certificate = kind_cluster.default.cluster_ca_certificate
}

# Configuración dinámica de Helm
provider "helm" {
  kubernetes {
    host                   = kind_cluster.default.endpoint
    client_certificate     = kind_cluster.default.client_certificate
    client_key             = kind_cluster.default.client_key
    cluster_ca_certificate = kind_cluster.default.cluster_ca_certificate
  }
}

# Instalación de Kube-Prometheus-Stack (Telemetría Level Tier 1)
resource "helm_release" "kube_prometheus_stack" {
  name             = "prometheus"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = "monitoring"
  create_namespace = true
  timeout          = 600

  # Aseguramos que Prometheus busque ServiceMonitors en todos los namespaces
  set {
    name  = "prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues"
    value = "false"
  }
}

resource "null_resource" "apply_manifests" {
  depends_on = [kind_cluster.default]

  provisioner "local-exec" {
    command = "kubectl apply -f ../manifests/app/ && kubectl apply -f ../manifests/security/"
  }
}
