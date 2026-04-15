/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dns_ingress.c - DNS 热点请求 XDP 程序。
 *
 * 第一版支持：
 *   - UDP/IPv4 DNS 查询解析
 *   - QTYPE=A / QCLASS=IN 的热点命中快速响应
 *   - 命中统计、解析失败统计、事件输出
 *   - 未命中则 XDP_PASS
 */

#include "common.h"

struct dns_hdr {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
} __attribute__((packed));

struct dns_answer {
	__be16 name_ptr;
	__be16 type;
	__be16 class_;
	__be32 ttl;
	__be16 rdlen;
	__be32 addr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_config);
} dns_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_stats);
} dns_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct dns_hot_key);
	__type(value, struct dns_hot_val);
} dns_hot_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} dns_events SEC(".maps");

static __always_inline void emit_event(__u32 event_type, const struct dns_hot_key *key, const struct dns_hot_val *val)
{
	struct dns_event ev = {};
	ev.ts_ns = bpf_ktime_get_ns();
	ev.event_type = event_type;
	if (val) {
		ev.ipv4 = val->ipv4;
		ev.ttl = val->ttl;
	}
	if (key) {
		ev.qtype = key->qtype;
		ev.qclass = key->qclass;
		__builtin_memcpy(ev.qname, key->qname, sizeof(ev.qname));
	}
	bpf_ringbuf_output(&dns_events, &ev, sizeof(ev), 0);
}

static __always_inline int parse_qname(const __u8 *pos, const __u8 *end, struct dns_hot_key *key, __u32 *question_end)
{
	__u32 out = 0;
	__u32 consumed = 0;
	__u32 labels = 0;

	__builtin_memset(key, 0, sizeof(*key));

	for (int label_idx = 0; label_idx < 32; label_idx++) {
		if (pos + 1 > end)
			return -1;

		__u8 len = *pos++;
		consumed++;
		if (len == 0)
			goto done;
		if ((len & 0xC0) != 0 || len > 63)
			return -1;
		if (labels > 0) {
			if (out + 1 >= DNS_QNAME_MAX)
				return -1;
			key->qname[out++] = '.';
		}
		labels++;

		for (int i = 0; i < 63; i++) {
			if (i >= len)
				break;
			if (pos + 1 > end)
				return -1;

			char c = (char)*pos++;
			consumed++;
			if (c >= 'A' && c <= 'Z')
				c = c + ('a' - 'A');
			if (out + 1 >= DNS_QNAME_MAX)
				return -1;
			key->qname[out++] = c;
		}
	}

	return -1;

done:
	key->qname[out] = '\0';
	if (pos + 4 > end)
		return -1;

	key->qtype = bpf_ntohs(*((const __be16 *)pos));
	pos += 2;
	key->qclass = bpf_ntohs(*((const __be16 *)pos));
	pos += 2;

	*question_end = sizeof(struct dns_hdr) + consumed + 4;
	return 0;
}

static __always_inline int dns_reply(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
				     struct udphdr *udp, struct dns_hdr *dns, __u32 question_end,
				     const struct dns_hot_val *val)
{
	const __u32 answer_len = sizeof(struct dns_answer);
	__u16 old_ip_len = bpf_ntohs(iph->tot_len);
	__u16 old_udp_len = bpf_ntohs(udp->len);
	__u16 new_ip_len = old_ip_len + answer_len;
	__u16 new_udp_len = old_udp_len + answer_len;

	if (bpf_xdp_adjust_tail(ctx, answer_len) < 0)
		return XDP_PASS;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	eth = data;
	iph = (struct iphdr *)(eth + 1);
	udp = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
	dns = (struct dns_hdr *)(udp + 1);

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if ((void *)dns + question_end + answer_len > data_end)
		return XDP_PASS;

	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	__builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

	__be32 old_saddr = iph->saddr;
	__be32 old_daddr = iph->daddr;
	iph->saddr = old_daddr;
	iph->daddr = old_saddr;
	iph->tot_len = bpf_htons(new_ip_len);
	iph->check = 0;
	iph->check = csum_ip_hdr(iph);

	__be16 old_source = udp->source;
	udp->source = udp->dest;
	udp->dest = old_source;
	udp->len = bpf_htons(new_udp_len);
	udp->check = 0;

	__u8 *answer_pos = (__u8 *)(dns) + question_end;
	struct dns_answer answer = {};
	answer.name_ptr = bpf_htons(0xC00C);
	answer.type = bpf_htons(1);
	answer.class_ = bpf_htons(1);
	answer.ttl = bpf_htonl(val->ttl);
	answer.rdlen = bpf_htons(4);
	answer.addr = val->ipv4;
	__builtin_memcpy(answer_pos, &answer, sizeof(answer));

	__u16 flags = bpf_ntohs(dns->flags);
	flags |= 0x8000; /* QR */
	flags |= 0x0400; /* AA */
	flags &= ~0x0200; /* TC */
	flags &= ~0x0080; /* RA */
	flags &= ~0x000F; /* RCODE */
	dns->flags = bpf_htons(flags);
	dns->ancount = bpf_htons(1);
	dns->nscount = 0;
	dns->arcount = 0;

	return XDP_TX;
}

SEC("xdp")
int dns_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udp;
	struct dns_hdr *dns;
	struct dns_hot_key key = {};
	struct dns_hot_val *val;
	struct dns_config *cfg;
	struct dns_stats *stats;
	__u32 zero = 0;
	__u32 question_end = 0;
	__u64 now = bpf_ktime_get_ns();

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	stats = bpf_map_lookup_elem(&dns_stats_map, &zero);
	if (stats)
		__sync_fetch_and_add(&stats->packets, 1);

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		if (stats)
			__sync_fetch_and_add(&stats->pass_through, 1);
		return XDP_PASS;
	}

	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end || iph->ihl != 5) {
		if (stats) {
			__sync_fetch_and_add(&stats->parse_errors, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PARSE_ERROR, NULL, NULL);
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_UDP) {
		if (stats)
			__sync_fetch_and_add(&stats->pass_through, 1);
		return XDP_PASS;
	}

	udp = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
	if ((void *)(udp + 1) > data_end) {
		if (stats) {
			__sync_fetch_and_add(&stats->parse_errors, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PARSE_ERROR, NULL, NULL);
		return XDP_PASS;
	}

	cfg = bpf_map_lookup_elem(&dns_config_map, &zero);
	if (!cfg) {
		if (stats)
			__sync_fetch_and_add(&stats->pass_through, 1);
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->dest) != cfg->listen_port) {
		if (stats)
			__sync_fetch_and_add(&stats->pass_through, 1);
		return XDP_PASS;
	}

	dns = (struct dns_hdr *)(udp + 1);
	if ((void *)(dns + 1) > data_end) {
		if (stats) {
			__sync_fetch_and_add(&stats->parse_errors, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PARSE_ERROR, NULL, NULL);
		return XDP_PASS;
	}

	if (bpf_ntohs(dns->qdcount) != 1) {
		if (stats) {
			__sync_fetch_and_add(&stats->unsupported, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PASS_THROUGH, NULL, NULL);
		return XDP_PASS;
	}

	if (parse_qname((__u8 *)(dns + 1), data_end, &key, &question_end) < 0) {
		if (stats) {
			__sync_fetch_and_add(&stats->parse_errors, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PARSE_ERROR, NULL, NULL);
		return XDP_PASS;
	}

	if (stats)
		__sync_fetch_and_add(&stats->dns_queries, 1);

	if (key.qtype != 1 || key.qclass != 1) {
		if (stats) {
			__sync_fetch_and_add(&stats->unsupported, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_PASS_THROUGH, &key, NULL);
		return XDP_PASS;
	}

	val = bpf_map_lookup_elem(&dns_hot_map, &key);
	if (!val) {
		if (stats) {
			__sync_fetch_and_add(&stats->hot_misses, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_HOT_MISS, &key, NULL);
		return XDP_PASS;
	}

	if (val->expires_ns != 0 && now > val->expires_ns) {
		bpf_map_delete_elem(&dns_hot_map, &key);
		if (stats) {
			__sync_fetch_and_add(&stats->hot_misses, 1);
			__sync_fetch_and_add(&stats->pass_through, 1);
		}
		emit_event(DNS_EVENT_HOT_EXPIRED, &key, val);
		return XDP_PASS;
	}

	__sync_fetch_and_add(&val->hits, 1);
	if (stats)
		__sync_fetch_and_add(&stats->hot_hits, 1);
	emit_event(DNS_EVENT_HOT_HIT, &key, val);

	int ret = dns_reply(ctx, eth, iph, udp, dns, question_end, val);
	if (ret == XDP_TX && stats)
		__sync_fetch_and_add(&stats->responses, 1);
	return ret;
}

char _license[] SEC("license") = "GPL";
