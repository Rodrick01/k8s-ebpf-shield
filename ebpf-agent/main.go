package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile/Dockerfile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf_xdp xdp_network.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf_kprobe kprobe_security.c -- -I../headers

const (
	maxCommandLen = 256
)

// KprobeEvent representa la estructura de datos que envía C a Go
type KprobeEvent struct {
	PID      uint32
	UID      uint32
	Comm     [16]byte
	Filename [maxCommandLen]byte
}

func main() {
	log.Println("=> Iniciando eBPF K8s Shield (Dual Layer)...")

	// 1. Remover límites de memoria bloqueada para eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo límites de memlock: %v", err)
	}

	// 2. Cargar objetos XDP
	var xdpObjs bpf_xdpObjects
	if err := loadBpf_xdpObjects(&xdpObjs, nil); err != nil {
		log.Fatalf("Error cargando objetos XDP: %v", err)
	}
	defer xdpObjs.Close()

	// 3. Cargar objetos Kprobe
	var kprobeObjs bpf_kprobeObjects
	if err := loadBpf_kprobeObjects(&kprobeObjs, nil); err != nil {
		log.Fatalf("Error cargando objetos Kprobe: %v", err)
	}
	defer kprobeObjs.Close()

	// 4. Atachar XDP a la interfaz eth0
	ifaceName := os.Getenv("SHIELD_IFACE")
	if ifaceName == "" {
		ifaceName = "eth0"
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Error buscando interfaz %s: %v", ifaceName, err)
	}
	log.Printf("=> Atachando XDP Shield a %s...", ifaceName)
	
	// Idempotencia: link.AttachXDP fallará si ya hay uno atachado a menos que usemos XDP_FLAGS_UPDATE_IF_NOEXIST o simplemente sobreescribimos
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpObjs.XdpShield,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error atachando XDP: %v", err)
	}
	defer xdpLink.Close()

	// 5. Atachar Kprobe a sys_execve
	log.Println("=> Atachando Kprobe Monitor a sys_execve...")
	kp, err := link.Kprobe("sys_execve", kprobeObjs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("Error atachando Kprobe: %v", err)
	}
	defer kp.Close()

	// 6. Leer eventos del RingBuffer (Kprobe)
	rd, err := ringbuf.NewReader(kprobeObjs.Events)
	if err != nil {
		log.Fatalf("Error creando ringbuf reader: %v", err)
	}
	defer rd.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Manejo de señales (Graceful Shutdown -> Idempotencia garantizada)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		log.Println("\n=> Recibida señal de apagado. Desmontando escudos eBPF...")
		cancel()
	}()

	// Loop de limpieza de mapa XDP (Evitar memory leak del LRU Hash)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Podríamos iterar el mapa y limpiar contadores viejos
				// Pero LRU_HASH expulsa los menos usados automáticamente.
				// Opcionalmente podemos resetear contadores altos.
			}
		}
	}()

	// Lógica de procesamiento de eventos (Syscalls)
	go func() {
		var event KprobeEvent
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Error leyendo ringbuf: %v", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("Error parseando evento: %v", err)
					continue
				}

				comm := strings.TrimRight(string(event.Comm[:]), "\x00")
				filename := strings.TrimRight(string(event.Filename[:]), "\x00")

				// Regla de detección de RCE / Shell iteractiva
				if strings.Contains(filename, "bash") || strings.Contains(filename, "sh") || strings.Contains(filename, "curl") || strings.Contains(filename, "wget") {
					log.Printf("[ALERTA CRÍTICA] Ejecución sospechosa detectada: UID=%d PID=%d Comm=%s Archivo=%s", event.UID, event.PID, comm, filename)
				}
			}
		}
	}()

	log.Println("=> Escudo eBPF ACTIVO. Bloqueando ataques de red (XDP) y auditando syscalls (Kprobe)...")
	<-ctx.Done()
	log.Println("=> Apagado completado de forma segura.")
}
