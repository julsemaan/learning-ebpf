#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

SEC("xdp")
int ping(struct xdp_md *ctx) {
    long icmp_type = lookup_ping_type(ctx);
    if (icmp_type == -1) // NOT ICMP
    {
      bpf_printk("NOT ICMP");
      return XDP_PASS;
    }
    else if(icmp_type == 0){
        bpf_printk("Hello ping echo reply");
        return XDP_PASS; 
    }
    else if(icmp_type == 8){
        bpf_printk("Hello ping echo");
        return XDP_PASS; 
    }
    else {
      bpf_printk("%d", icmp_type);
      return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
