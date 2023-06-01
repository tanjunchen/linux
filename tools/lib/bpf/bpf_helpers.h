/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/*
 * Note that bpf programs need to include either
 * vmlinux.h (auto-generated from BTF) or linux/types.h
 * in advance since bpf_helper_defs.h uses such types
 * as __u64.
 */
#include "bpf_helper_defs.h"

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

// 调试 BPF 程序
// 打印日志大法
// bpf_printk("tcp_v4_connect latency_us: %u", latency_us); kernel 5.2+
// bpf_trace_printk()
// 使用限制：
// 最多只能带 3 个参数（这是因为 eBPF helpers 最多只能带 5 个参数，前面 fmt 和 fmt_size 已经占了两个了）；
// 使用该函数的代码必须是 GPL 兼容的；
// 前面已经提到，格式字符串支持的类型有限。


// 用 BPF 程序 trace 另一个 BPF 程序
// BPF trampoline 是 内核函数和 BPF 程序之间、BPF 程序和其他 BPF 程序之间的桥梁（更多介绍见附录）。 
// 使用场景之一是 tracing 其他 BPF 程序，例如 XDP 程序。 
// 现在能向任何网络类型的 BPF 程序 attach 类似 fentry/fexit 的 BPF 程序，
// 因此能够看到 XDP、TC、LWT、cgroup 等任何类型 BPF 程序中包的进进出出，
// 而不会影 响到这些程序的执行，大大降低了基于 BPF 的网络排障难度。
// BPF trampoline 其他使用场景：
// fentry/fexit BPF 程序：功能与 kprobe/kretprobe 类似，但性能更好，几乎没有性能开销（practically zero overhead）；
// 动态链接 BPF 程序（dynamicly link BPF programs）。
// 在 tracing、networking、cgroup BPF 程序中，是比 prog array 和 prog link list 更加通用的机制。
// 在很多情况下，可直接作为基于 bpf_tail_call 程序链的一种替代方案。
// kernel 5.5+

// 设置断点，单步调试
// 参见 http://arthurchiao.art/blog/linux-socket-filtering-aka-bpf-zh/

/**
fentry/fexit 相比 kprobe/kretprobe 的优势
性能更好。

数据中心中的一些真实 tracing 场景显示， 某些关键的内核函数（例如 tcp_retransmit_skb）有 2 个甚至更多永远活跃的 kprobes， 其他一些函数同时有 kprobe and kretprobe。

所以，最大化内核代码和 BPF 程序的执行速度就非常有必要。因此 在每个新程序 attach 时或者 detach 时，BPF trampoline 都会重新生成，以保证最高性能。 （另外在设计上，从 trampoline detach BPF 程序不会失败。）

能拿到的信息更多。

fentry BPF 程序能拿到内核函数参数， 而
fexit BPF 程序除了能拿到函数参数，还能拿到函数返回值；而 kretprobe 只能拿到返回结果。
kprobe BPF 程序通常将函数参数记录到一个 map 中，然后 kretprobe 从 map 中 拿出参数，并和返回值一起做一些分析处理。fexit BPF 程序加速了这个典型的使用场景。

可用性更好。

和普通 C 程序一样，直接对指针参数解引用， 不再需要各种繁琐的 probe read helpers 了。

限制：fentry/fexit BPF 程序需要更高的内核版本（5.5+）才能支持。
*/

// 这是内核 libbpf 库提供的一个宏：kernel 5.2+ 
/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

/*
 * Helper macro to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)				\
	({							\
		void *__mptr = (void *)(ptr);			\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

/*
 * Helper macro to throw a compilation error if __bpf_unreachable() gets
 * built into the resulting code. This works given BPF back end does not
 * implement __builtin_trap(). This is useful to assert that certain paths
 * of the program code are never used and hence eliminated by the compiler.
 *
 * For example, consider a switch statement that covers known cases used by
 * the program. __bpf_unreachable() can then reside in the default case. If
 * the program gets extended such that a case is not covered in the switch
 * statement, then it will throw a build error due to the default case not
 * being compiled out.
 */
#ifndef __bpf_unreachable
# define __bpf_unreachable()	__builtin_trap()
#endif

/*
 * Helper function to perform a tail call with a constant/immediate map slot.
 */
#if __clang_major__ >= 8 && defined(__bpf__)
static __always_inline void
bpf_tail_call_static(void *ctx, const void *map, const __u32 slot)
{
	if (!__builtin_constant_p(slot))
		__bpf_unreachable();

	/*
	 * Provide a hard guarantee that LLVM won't optimize setting r2 (map
	 * pointer) and r3 (constant map index) from _different paths_ ending
	 * up at the _same_ call insn as otherwise we won't be able to use the
	 * jmpq/nopl retpoline-free patching by the x86-64 JIT in the kernel
	 * given they mismatch. See also d2e4c1e6c294 ("bpf: Constant map key
	 * tracking for prog array pokes") for details on verifier tracking.
	 *
	 * Note on clobber list: we need to stay in-line with BPF calling
	 * convention, so even if we don't end up using r0, r4, r5, we need
	 * to mark them as clobber so that LLVM doesn't end up using them
	 * before / after the call.
	 */
	asm volatile("r1 = %[ctx]\n\t"
		     "r2 = %[map]\n\t"
		     "r3 = %[slot]\n\t"
		     "call 12"
		     :: [ctx]"r"(ctx), [map]"r"(map), [slot]"i"(slot)
		     : "r0", "r1", "r2", "r3", "r4", "r5");
}
#endif

/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	/* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
	LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
	TRI_NO = 0,
	TRI_YES = 1,
	TRI_MODULE = 2,
};

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#endif
