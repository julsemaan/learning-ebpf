#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
struct data_t {
    char command[16];
};
BPF_HASH(counter_table, struct data_t);

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   struct data_t data = {};

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_trace_printk("%s", data.command);

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&data);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&data, &counter);
   return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall, fn_name="hello")
syscall = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.command.decode()}: {v.value}\t"
    print(s)
