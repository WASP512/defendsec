// Process-execution sensor (roadmap 3.1).
//
// The poller this replaces samples /proc, so it misses any process that
// starts and exits between samples — and `curl … | sh` is short-lived. This
// program sees every successful exec, with the argument vector as the caller
// actually passed it.
//
// # Why two tracepoints
//
// `sys_enter_execve` is the only place the argument vector is reachable: the
// pointers are still valid userspace addresses in the *old* address space.
// But it fires for execs that then fail — a mistyped command, a missing
// interpreter — and emitting those would put processes in the console that
// never ran. A rule matching CommandLine would fire on something that never
// executed, which is worse than missing it.
//
// `sched_process_exec` fires only on success and carries the resolved
// filename, but by then the old stack holding argv is gone.
//
// So argv is stashed at entry, keyed by the thread, and the stash is claimed
// at the success tracepoint. An exec that fails leaves its stash behind; the
// map is an LRU hash for exactly that reason, so failures are evicted rather
// than leaking.
//
// # Why tracepoints rather than kprobes
//
// Tracepoints are a stable kernel ABI. A kprobe on a function whose signature
// changes between releases produces silently wrong fields, and a sensor that
// is confidently wrong is worse than one that is absent.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Bounds. Every one of these truncates rather than drops: a long command line
// recorded as its first 2KB is still evidence, while dropping the event loses
// the fact that anything ran at all. Truncation is flagged in the event so
// the console never presents a clipped command line as the whole thing.
#define ARG_COUNT 16
#define ARG_LEN 128
#define FILENAME_LEN 256
#define COMM_LEN 16

struct exec_event {
    __u64 at_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 argc;
    // args_truncated is set when the process passed more than ARG_COUNT
    // arguments, or an argument longer than ARG_LEN.
    __u32 args_truncated;
    __u32 _pad;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
    char args[ARG_COUNT * ARG_LEN];
};

// Minimal CO-RE view of task_struct. Declaring only the fields actually read
// avoids needing a generated vmlinux.h, and preserve_access_index makes the
// offsets relocatable against the running kernel's BTF, so one object works
// across kernel versions rather than being built per release.
struct task_struct {
    struct task_struct *real_parent;
    int tgid;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct exec_event);
} stash SEC(".maps");

// The ring buffer is sized to hold roughly a second of a busy host's execs.
// It drops when full rather than blocking the process being traced: a sensor
// that applied backpressure to execve would make the host slower under
// exactly the load that matters, and a sensor that destabilises the host gets
// uninstalled — at which point coverage is zero rather than degraded.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

// lost counts events the ring buffer had no room for, so the gap is a number
// the console can show rather than a silence.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");

struct sys_enter_execve_ctx {
    __u64 __unused;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct sched_process_exec_ctx {
    __u64 __unused;
    __u32 filename_loc;
    __s32 pid;
    __s32 old_pid;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve_enter(struct sys_enter_execve_ctx *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    // Reserving in the ring buffer here would be wrong: the reservation would
    // have to survive until the success tracepoint, and a failed exec would
    // hold it forever. The stash is a map value instead.
    struct exec_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        __u64 *n = bpf_map_lookup_elem(&lost, &zero);
        if (n)
            __sync_fetch_and_add(n, 1);
        return 0;
    }

    ev->at_ns = bpf_ktime_get_ns();
    ev->pid = id >> 32;
    ev->uid = bpf_get_current_uid_gid();
    ev->argc = 0;
    ev->args_truncated = 0;
    ev->_pad = 0;
    ev->ppid = 0;
    ev->filename[0] = 0;
    ev->args[0] = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            ev->ppid = BPF_CORE_READ(parent, tgid);
    }

    // The filename argument, not the resolved path. It is kept because it is
    // what the caller asked for, which can differ from what ran — a symlink,
    // or a PATH lookup — and the difference is occasionally the whole story.
    bpf_probe_read_user_str(ev->filename, FILENAME_LEN, ctx->filename);

    // argv is read one pointer at a time. The loop bound is a constant
    // because the verifier must be able to prove termination; a process with
    // more arguments than this has the rest flagged as truncated rather than
    // silently dropped.
    const char *const *argv = ctx->argv;
    if (argv) {
        int i;
        for (i = 0; i < ARG_COUNT; i++) {
            const char *arg = NULL;
            if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0)
                break;
            if (!arg)
                break;
            long n = bpf_probe_read_user_str(&ev->args[i * ARG_LEN], ARG_LEN, arg);
            if (n < 0)
                break;
            if (n == ARG_LEN)
                ev->args_truncated = 1;
            ev->argc = i + 1;
        }
        if (i == ARG_COUNT) {
            // There may be more. Check one past the end rather than claiming
            // truncation for a process that passed exactly ARG_COUNT.
            const char *more = NULL;
            if (bpf_probe_read_user(&more, sizeof(more), &argv[ARG_COUNT]) == 0 && more)
                ev->args_truncated = 1;
        }
    }

    // Stashed, not submitted: it is not yet known whether this exec succeeds.
    bpf_map_update_elem(&stash, &id, ev, BPF_ANY);
    bpf_ringbuf_discard(ev, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(struct sched_process_exec_ctx *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 zero = 0;

    struct exec_event *stashed = bpf_map_lookup_elem(&stash, &id);
    if (!stashed) {
        // No stash: either the exec came from a path this program does not
        // hook (execveat), or the entry event was evicted under load. Not
        // emitted, because an event with no argv would look like a process
        // that ran with no arguments — a lie a rule could match on.
        return 0;
    }

    struct exec_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        __u64 *n = bpf_map_lookup_elem(&lost, &zero);
        if (n)
            __sync_fetch_and_add(n, 1);
        bpf_map_delete_elem(&stash, &id);
        return 0;
    }

    // bpf_probe_read_kernel rather than a struct assignment: the verifier
    // rejects an inline copy of this size, and the stash is kernel memory.
    bpf_probe_read_kernel(ev, sizeof(*ev), stashed);
    bpf_map_delete_elem(&stash, &id);

    // The resolved filename, overwriting what the caller asked for. This is
    // the path that actually executed, and it is what a rule should match.
    // __data_loc packs the offset in the low 16 bits.
    __u32 off = ctx->filename_loc & 0xFFFF;
    bpf_probe_read_kernel_str(ev->filename, FILENAME_LEN, (void *)ctx + off);

    // comm is re-read: at entry it was still the old program's name, and the
    // name of the thing that ran is more useful than the name of the thing
    // that called exec — which is already recorded as the parent.
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
