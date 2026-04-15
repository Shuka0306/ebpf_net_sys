/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - DNS XDP 程序与用户态共享的最小类型与 helper 声明。
 */
#ifndef __DNS_EBPF_COMMON_H
#define __DNS_EBPF_COMMON_H

#include <stdint.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* BPF map types used by the first phase. */
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27

/* XDP action codes. */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct ethhdr {
	__u8 h_dest[ETH_ALEN];
	__u8 h_source[ETH_ALEN];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl : 4;
	__u8 version : 4;
#else
	__u8 version : 4;
	__u8 ihl : 4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef bpf_htons
#define bpf_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef bpf_htonl
#define bpf_htonl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#endif

#ifndef bpf_ntohl
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#endif

#define DNS_QNAME_MAX 128

enum dns_event_type {
	DNS_EVENT_PARSE_ERROR = 1,
	DNS_EVENT_HOT_HIT = 2,
	DNS_EVENT_HOT_MISS = 3,
	DNS_EVENT_HOT_EXPIRED = 4,
	DNS_EVENT_PASS_THROUGH = 5,
};

struct dns_config {
	__u16 listen_port;   /* host order */
	__u16 _pad0;
	__u32 max_qname_len; /* first version fixed at 128 */
	__u32 _pad1;
};

struct dns_stats {
	__u64 packets;
	__u64 dns_queries;
	__u64 parse_errors;
	__u64 unsupported;
	__u64 hot_hits;
	__u64 hot_misses;
	__u64 pass_through;
	__u64 responses;
	__u64 truncated;
};

struct dns_hot_key {
	char qname[DNS_QNAME_MAX];
	__u16 qtype;  /* host order */
	__u16 qclass; /* host order */
};

struct dns_hot_val {
	__u32 ipv4;      /* network order */
	__u32 ttl;       /* seconds */
	__u64 expires_ns;
	__u64 hits;
};

struct dns_event {
	__u64 ts_ns;
	__u32 event_type;
	__u32 ipv4;
	__u32 ttl;
	__u16 qtype;
	__u16 qclass;
	char qname[DNS_QNAME_MAX];
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_ringbuf_output)(void *ringbuf, const void *data, __u64 size, __u64 flags) = (void *)130;
static long (*bpf_xdp_adjust_tail)(struct xdp_md *xdp_md, int delta) = (void *)65;
static __s64 (*bpf_csum_diff)(const __be32 *from, __u32 from_size, const __be32 *to, __u32 to_size, __wsum seed) = (void *)28;

static __always_inline __u16 fold_csum(__u64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16 csum_ip_hdr(struct iphdr *iph)
{
	__u64 csum = 0;
	iph->check = 0;
	csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0);
	return fold_csum(csum);
}

#endif /* __DNS_EBPF_COMMON_H */
