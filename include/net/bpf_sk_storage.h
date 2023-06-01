/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Facebook */
#ifndef _BPF_SK_STORAGE_H
#define _BPF_SK_STORAGE_H

#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <net/sock.h>
#include <uapi/linux/sock_diag.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_local_storage.h>

struct sock;

void bpf_sk_storage_free(struct sock *sk);

extern const struct bpf_func_proto bpf_sk_storage_get_proto;
extern const struct bpf_func_proto bpf_sk_storage_delete_proto;

struct bpf_local_storage_elem;
struct bpf_sk_storage_diag;
struct sk_buff;
struct nlattr;
struct sock;

#ifdef CONFIG_BPF_SYSCALL
int bpf_sk_storage_clone(const struct sock *sk, struct sock *newsk);
struct bpf_sk_storage_diag *
bpf_sk_storage_diag_alloc(const struct nlattr *nla_stgs);
void bpf_sk_storage_diag_free(struct bpf_sk_storage_diag *diag);
int bpf_sk_storage_diag_put(struct bpf_sk_storage_diag *diag,
			    struct sock *sk, struct sk_buff *skb,
			    int stg_array_type,
			    unsigned int *res_diag_size);
#else
static inline int bpf_sk_storage_clone(const struct sock *sk,
				       struct sock *newsk)
{
	return 0;
}
static inline struct bpf_sk_storage_diag *
bpf_sk_storage_diag_alloc(const struct nlattr *nla)
{
	return NULL;
}
static inline void bpf_sk_storage_diag_free(struct bpf_sk_storage_diag *diag)
{
}
static inline int bpf_sk_storage_diag_put(struct bpf_sk_storage_diag *diag,
					  struct sock *sk, struct sk_buff *skb,
					  int stg_array_type,
					  unsigned int *res_diag_size)
{
	return 0;
}
#endif

#endif /* _BPF_SK_STORAGE_H */

// 随着能用 BPF 来编写越来越多的网卡功能和特性，一个很自然的需求就是： BPF 程序希望将某些信息关联到特定的 socket。
// 例如，明天我可能就会用 BPF 开发一个新的 TCP CC 算法，希望将特定连接的少量数据存放到对应的 socket，比如是 RTT 采样。

// 解决方式：
// hashtab way 定义一个 bpf hashmap，key 是 4-tuple，value 是数据。
// bpf_sk_storage way 直接将数据存储到 socket（sk）自身，数据跟着 socket 走；当 socket 关闭时，数据会自动清理；

// 案例：
// 首先定义一个 BPF_MAP_TYPE_SK_STORAGE 类型的 BPF map
// Key 必须是一个 socket fd
// Value 可以是任意的，存储希望存储到 sk 中的数据

/** 这里想说明的是，用户空间程序必须持有一个 socket 文件描述符，但对于某些共享 map， 有些进程没有这个 fd 信息，怎么办呢？

必须要持有（hold）对应 socket 的文件描述符
对于已共享 map，其他进程可能无法 hold fd
其他一些 map 也有类似情况（as a value），例如 sockmap, reuseport_array 等等

已经提出了每个 socket 一个 ID，这个 ID 就是 socket cookie 是否有通用办法，从 socket cookie 中获取 fd？还没定论。
每个 socket （sk）一个 ID：已经有 sk cookie 了
A generic way to do sk cookie => fd?
*/
