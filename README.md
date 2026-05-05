# Kubernetes HA + eBPF Security Shield

Este repositorio implementa una arquitectura de **Seguridad Defensiva Zero-Trust de Nivel Dios** en un clúster de Kubernetes, diseñado y construido con principios estrictos de Site Reliability Engineering (SRE) e Idempotencia.

El proyecto demuestra que un clúster no solo se debe desplegar correctamente (Alta Disponibilidad), sino que debe tener la capacidad de **defenderse de forma autónoma** contra ataques de red volumétricos (DDoS) y vulnerabilidades internas (Ejecución de Código Remoto - RCE).

## 🛡️ Arquitectura Multi-Capa

### 1. La "Carnada": K8s HA Workload
Un despliegue "Normie" pero con rigor de Tier 1:
- **Topology Spread Constraints:** Los Pods de NGINX se fuerzan a vivir en nodos físicos distintos. Si cae un nodo, el servicio ni parpadea.
- **Pod Disruption Budgets (PDB):** K8s no permitirá que operaciones de mantenimiento (draining) bajen la disponibilidad por debajo de 2 réplicas.
- **Horizontal Pod Autoscaler (HPA):** Auto-escalado reactivo en base al consumo de CPU.

### 2. El Escudo: Agente eBPF (XDP + Kprobes)
En lugar de depender únicamente del Ingress Controller o firewalls tradicionales, este proyecto despliega un `DaemonSet` privilegiado en **todos los nodos**. Este DaemonSet carga programas eBPF directamente en el Kernel de Linux del worker node:

- **Capa 1 (Network Data Plane - XDP):** 
  El programa XDP intercepta los paquetes directamente en el driver de la tarjeta de red (NIC), antes de que Linux asigne recursos de memoria (`sk_buff`). Identifica anomalías TCP (Xmas Scans, SYN-FIN) y bloquea instantáneamente SYN Floods volumétricos. Resultado: **Mitigación de DDoS con impacto cero en la CPU del nodo.**
  
- **Capa 2 (OS Control Plane - Kprobes):**
  Enganchado a la syscall `sys_enter_execve`, el agente vigila qué comandos se ejecutan dentro del clúster. Si un atacante logra un RCE y trata de abrir `/bin/bash` o descargar un payload con `curl` dentro de un Pod, el agente lo detecta en tiempo real sin requerir modificaciones en las aplicaciones.

## 🚀 Despliegue Idempotente ("Plug and Play")

Hemos implementado un `Makefile` puramente idempotente. No importa cuántas veces lo corras, asegurará el estado deseado sin efectos secundarios.

### Requisitos:
- Docker instalado
- `kind` (Kubernetes in Docker) instalado
- `kubectl` instalado

### Iniciar el entorno completo:
```bash
make all
```

1. Evalúa si el clúster `ebpf-shield-cluster` de 3 nodos ya existe. Si no, lo crea de forma limpia.
2. Aplica los manifiestos HA del NGINX.
3. Despliega el DaemonSet del Agente eBPF en todo el clúster.

### Verificar la Protección eBPF:
Puedes verificar cómo el escudo eBPF se atacha revisando los logs del DaemonSet:
```bash
kubectl logs -n kube-system -l app=ebpf-shield
```

## 🏗️ Compilación y Desarrollo

Si deseas modificar la lógica del Escudo eBPF (C) o del orquestador (Go), puedes recompilar la imagen Docker localmente. El orquestador Go asegura la idempotencia a nivel Kernel (desmonta gracefully los links eBPF antiguos y libera los Mapas al recibir `SIGTERM`).

```bash
cd ebpf-agent
docker build -t rodrick01/ebpf-shield:latest .
kind load docker-image rodrick01/ebpf-shield:latest --name ebpf-shield-cluster
```
