#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("classifier/bgmi_tweak")
int bgmi_bullet_reg(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet header check
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;

    // IP header check
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return TC_ACT_OK;

    // UDP check (BGMI Protocol)
    if (iph->protocol == IPPROTO_UDP) {
        // Yahan packet ko mark kar rahe hain (Hit-reg bypass logic)
        skb->mark = 1; 
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
