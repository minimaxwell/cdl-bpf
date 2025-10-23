#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

struct dnshdr {
	__be16 trans_id;
	__be16 flags;
	__be16 nr_quest;
	__be16 nr_answ;
	__be16 nr_auth_rr;
	__be16 add_rr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, char[128]);
} array SEC(".maps");

struct dns_lookup_ctx {
	const char *query;
	unsigned int match;
};

static int __strncmp(const void *m1, const void *m2, unsigned int len)
{
	const unsigned char *s1 = m1;
	const unsigned char *s2 = m2;
	int i, delta = 0;

	for (i = 0; i < len; i++) {
		delta = s1[i] - s2[i];
		if (delta || s1[i] == 0 || s2[i] == 0)
			break;
	}
	return delta;
}

static long dns_lookup(struct bpf_map *map, __u32 *key, void *value,
		       void *context)
{
	struct dns_lookup_ctx *ctx = context;
	char *dns_query = (char *)value;

	//bpf_probe_read(*dns_query, 128, value);

	if (!__strncmp(ctx->query, dns_query, 128)) {
		ctx->match = 1;
		return 1;
	}

	return 0;
}

SEC("tc")
int dns_catcher(struct __sk_buff *skb)
{
	const char fmt[] = "On a une query DNS pour %s";
	const char drop_fmt[] = "On drop %s";
	unsigned int offs, pos = 0;
	struct dns_lookup_ctx ctx = { .match = 0 };
	struct dnshdr dnshdr;
	struct udphdr udphdr;
	struct iphdr iph;
	char query[128] = {0};
	int ret;
	char c;

	/* IPv4 only*/
	ret = bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
	if (ret)
		return TC_ACT_OK;

	if (iph.protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	ret = bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4),
				 &udphdr, sizeof(udphdr));
	if (ret)
		return TC_ACT_OK;

	if (udphdr.dest != __bpf_constant_htons(53))
		return TC_ACT_OK;

	ret = bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4) + sizeof(udphdr),
				 &dnshdr, sizeof(udphdr));
	if (ret)
		return TC_ACT_OK;

	if (!(dnshdr.flags & __bpf_constant_htons(0x0100)))
		return TC_ACT_OK;

	offs = ETH_HLEN + (iph.ihl * 4) + sizeof(udphdr) + sizeof(dnshdr);

	/* Taille */
	ret = bpf_skb_load_bytes(skb, offs, &c, 1);
	if (ret)
		return TC_ACT_OK;

	pos = 0;

	while (c != '\0') {
		ret = bpf_skb_load_bytes(skb, offs + pos + 1, &c , 1);
		if (ret)
			return TC_ACT_OK;

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
			query[pos] = c;
		else if (c != '\0')
			query[pos] = '.';
		pos++;

		if (pos == 128 || c == '\0')
			break;
	}

	bpf_trace_printk(fmt, sizeof(fmt), query);

	ctx.query = query;

	bpf_for_each_map_elem(&array, dns_lookup, &ctx, 0);

	if (ctx.match) {
		bpf_trace_printk(drop_fmt, sizeof(drop_fmt), ctx.query);
		return TC_ACT_SHOT;
	}
	/* Print payload */

	return TC_ACT_OK;
}

 char __license[] SEC("license") = "GPL";
