#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);  // L4 协议类型（长度是 uint8），例如 IPPROTO_TCP，范围是 0~255
	__type(value, long); // 累计包长（skb->len）
	__uint(max_entries, 256);
} my_map SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;
 	// 注意：在用户态程序和这段 BPF 程序里都没有往 my_map 里插入数据；
    //   * 如果这是 hash map 类型，那下面的 lookup 一定失败，因为我们没插入过任何数据；
    //   * 但这里是 array 类型，而且 index 表示的 L4 协议类型，在 IP 头里占一个字节，因此范围在 255 以内；
    //     又 map 的长度声明为 256，所以这里的 lookup 一定能定位到 array 的某个位置，即查找一定成功。
	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}
char _license[] SEC("license") = "GPL";
