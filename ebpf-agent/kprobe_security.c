// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMMAND_LEN 256

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[MAX_COMMAND_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    struct event *e;

    // Reservar espacio en el ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Obtener información del proceso
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Obtener el nombre del archivo ejecutado (el primer argumento de execve)
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Enviar el evento a user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
