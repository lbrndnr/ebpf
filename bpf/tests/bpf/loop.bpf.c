#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "ebpf/tracing.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("syscall")
int trace_loop(void *ctx) {
    for (int i = 0; i < 1000; i++) {
        bpf_debug("asdf qwer asdf qwer %d", i);
    }

    return 0;
}
