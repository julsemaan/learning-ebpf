#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
struct key_t {
    char command[16];
    char call[6];
};
BPF_HASH(counter_table, struct key_t);

int execve__call(void *ctx) {
    return record("execve");
}

int openat__call(void *ctx) {
    return record("openat");
}

int write__call(void *ctx) {
    return record("write");
}

int record(char call[6]) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   struct key_t key = {};

   bpf_get_current_comm(&key.command, sizeof(key.command));
   bpf_trace_printk("%s", key.command);
   strcpy(key.call, call);

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&key);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&key, &counter);
   return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="execve__call")
syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall, fn_name="openat__call")
syscall = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall, fn_name="write__call")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.command.decode()}|{k.call.decode()}: {v.value}\t"
    print(s)
