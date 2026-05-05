FROM golang:1.22-alpine AS builder

# Instalar dependencias para compilar eBPF (Clang, llvm, libbpf)
RUN apk add --no-cache \
    clang \
    llvm \
    make \
    linux-headers \
    gcc \
    musl-dev \
    git

WORKDIR /app

# Copiar archivos
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generar y compilar
# BPF_CLANG y BPF_CFLAGS aseguran la correcta compilación cross-arch
ENV BPF_CLANG=clang
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"

# En alpine, linux-headers están en /usr/include
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux go build -o ebpf-agent .

# Etapa final: Runtime mínimo
FROM alpine:latest
RUN apk add --no-cache iproute2

WORKDIR /app
COPY --from=builder /app/ebpf-agent .

CMD ["./ebpf-agent"]
