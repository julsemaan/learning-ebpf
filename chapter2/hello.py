#!/usr/bin/python3  
from bcc import BPF
import sys

program = r"""
int hello(struct xdp_md *ctx)
{
    return XDP_PASS;
}
"""

b = BPF(text=program)
device = "ens19" #2
fn = b.load_func("hello", BPF.XDP) #4
b.attach_xdp(device, fn, 0) #5

while True:
    sys.stdin.read(1)

b.remove_xdp(device, 0) #11

