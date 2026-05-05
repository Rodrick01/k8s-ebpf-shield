// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // IP Source
    __type(value, __u64); // SYN packet count
    __uint(max_entries, 100000);
} syn_counter SEC(".maps");

// Umbral de SYNs por ventana de tiempo (manejado desde Go)
#define SYN_THRESHOLD 10000

SEC("xdp")
int xdp_shield(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Capa 1: Invalid TCP Flags (Xmas, Null)
    // Null scan: sin banderas
    if (tcp->fin == 0 && tcp->syn == 0 && tcp->rst == 0 && tcp->psh == 0 && tcp->ack == 0 && tcp->urg == 0) {
        return XDP_DROP;
    }
    // Xmas scan: FIN, PSH, URG
    if (tcp->fin && tcp->psh && tcp->urg) {
        return XDP_DROP;
    }
    // SYN-FIN (Inválido)
    if (tcp->syn && tcp->fin) {
        return XDP_DROP;
    }

    // Capa 2: SYN Flood Rate Limiting
    if (tcp->syn && !tcp->ack) {
        __u32 src_ip = ip->saddr;
        __u64 *count = bpf_map_lookup_elem(&syn_counter, &src_ip);
        if (count) {
            __sync_fetch_and_add(count, 1);
            if (*count > SYN_THRESHOLD) {
                // Rate limit superado, dropear
                return XDP_DROP;
            }
        } else {
            __u64 initial = 1;
            bpf_map_update_elem(&syn_counter, &src_ip, &initial, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
