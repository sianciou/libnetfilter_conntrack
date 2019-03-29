/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"

static int __snprintf_l3protocol(char *buf,
				 unsigned int len,
				 const struct nf_conntrack *ct)
{
	//tcp 6
	return (snprintf(buf, len, "%s ", 
		l3proto2str[ct->head.orig.l3protonum] == NULL ?
		"unknown" : l3proto2str[ct->head.orig.l3protonum]));
}

int __snprintf_protocol(char *buf,
			unsigned int len,
			const struct nf_conntrack *ct)
{
	//tcp 6
	return (snprintf(buf, len, "%s ", 
		proto2str[ct->head.orig.protonum] == NULL ?
		"unknown" : proto2str[ct->head.orig.protonum])); 
}

static int __snprintf_address_ipv4(char *buf,
				   unsigned int len,
				   const struct __nfct_tuple *tuple,
				   const char *src_tag,
				   const char *dst_tag)
{
	int ret, size = 0, offset = 0;
	struct in_addr src = { .s_addr = tuple->src.v4 };
	struct in_addr dst = { .s_addr = tuple->dst.v4 };
	//src= dst= 
	ret = snprintf(buf, len, "%s ", inet_ntoa(src), ntohs(tuple->l4src.tcp.port));
	BUFFER_SIZE(ret, size, len, offset);


	return size;
}

static int __snprintf_address_ipv6(char *buf,
				   unsigned int len,
				   const struct __nfct_tuple *tuple,
				   const char *src_tag,
				   const char *dst_tag)
{
	int ret, size = 0, offset = 0;
	struct in6_addr src;
	struct in6_addr dst;
	char tmp[INET6_ADDRSTRLEN];

	memcpy(&src, &tuple->src.v6, sizeof(struct in6_addr));
	memcpy(&dst, &tuple->dst.v6, sizeof(struct in6_addr));

	if (!inet_ntop(AF_INET6, &src, tmp, sizeof(tmp)))
		return -1;
	//src= dst=
	ret = snprintf(buf, len, "%s ", tmp);
	BUFFER_SIZE(ret, size, len, offset);


	return size;
}

int __snprintf_address(char *buf,
		       unsigned int len,
		       const struct __nfct_tuple *tuple,
		       const char *src_tag,
		       const char *dst_tag)
{
	int size = 0;

	switch (tuple->l3protonum) {
	case AF_INET:
		size = __snprintf_address_ipv4(buf, len, tuple,
						src_tag, dst_tag);
		break;

    case AF_INET6:
		size = __snprintf_address_ipv6(buf, len, tuple,
						src_tag, dst_tag);
		break;

	}

	return size;
}

int __snprintf_proto(char *buf, 
		     unsigned int len,
		     const struct __nfct_tuple *tuple)
{
	int size = 0;

	switch(tuple->protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		//sport= dport=
		return snprintf(buf, len, "%u %u ",
			        ntohs(tuple->l4src.tcp.port),
			        ntohs(tuple->l4dst.tcp.port));
		break;

    case IPPROTO_GRE:
		return snprintf(buf, len, "srckey=0x%x dstkey=0x%x ",
			        ntohs(tuple->l4src.all),
			        ntohs(tuple->l4dst.all));
		break;
        
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		/* The ID only makes sense some ICMP messages but we want to
		 * display the same output that /proc/net/ip_conntrack does */
		return (snprintf(buf, len, "type=%d code=%d id=%d ",
			tuple->l4dst.icmp.type,
			tuple->l4dst.icmp.code,
			ntohs(tuple->l4src.icmp.id)));
		break;
        
	}

	return size;
}


static int __snprintf_counters(char *buf,
			       unsigned int len,
			       struct nf_conntrack *ct,
			       int origdir, int repldir)
{
	//packets= bytes=
    return (snprintf(buf, len, "%llu %llu",
                (unsigned long long) ct->counters[origdir].bytes,
                (unsigned long long) ct->counters[repldir].bytes));
}

static int
__snprintf_timestamp_start(char *buf, unsigned int len,
			   const struct nf_conntrack *ct)
{
	time_t start = (time_t)(ct->timestamp.start / NSEC_PER_SEC);
	char *tmp = ctime(&start);

	/* overwrite \n in the ctime() output. */
	tmp[strlen(tmp)-1] = '\0';
	return (snprintf(buf, len, "[start=%s] ", tmp));
}

static int
__snprintf_timestamp_stop(char *buf, unsigned int len,
			  const struct nf_conntrack *ct)
{
	time_t stop = (time_t)(ct->timestamp.stop / NSEC_PER_SEC);
	char *tmp = ctime(&stop);

	/* overwrite \n in the ctime() output. */
	tmp[strlen(tmp)-1] = '\0';
	return (snprintf(buf, len, "[stop=%s] ", tmp));
}

static int
__snprintf_timestamp_delta(char *buf, unsigned int len,
			   const struct nf_conntrack *ct)
{
	time_t delta_time, stop;

	if (ct->timestamp.stop == 0)
		time(&stop);
	else
		stop = (time_t)(ct->timestamp.stop / NSEC_PER_SEC);

	delta_time = stop - (time_t)(ct->timestamp.start / NSEC_PER_SEC);

	return (snprintf(buf, len, "delta-time=%llu ",
			(unsigned long long)delta_time));
}

int
__snprintf_connlabels(char *buf, unsigned int len,
		      struct nfct_labelmap *map,
		      const struct nfct_bitmask *b, const char *fmt)
{
	unsigned int i, max;
	int ret, size = 0, offset = 0;

	max = nfct_bitmask_maxbit(b);
	for (i = 0; i <= max && len; i++) {
		const char *name;
		if (!nfct_bitmask_test_bit(b, i))
			continue;
		name = nfct_labelmap_get_name(map, i);
		if (!name || strcmp(name, "") == 0)
			continue;

		ret = snprintf(buf + offset, len, fmt, name);
		BUFFER_SIZE(ret, size, len, offset);
	}
	return size;
}

static int
__snprintf_clabels(char *buf, unsigned int len,
		   const struct nf_conntrack *ct, struct nfct_labelmap *map)
{
	const struct nfct_bitmask *b = nfct_get_attr(ct, ATTR_CONNLABELS);
	int ret, size = 0, offset = 0;

	if (!b)
		return 0;

	ret = snprintf(buf, len, "labels=");
	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_connlabels(buf + offset, len, map, b, "%s,");

	BUFFER_SIZE(ret, size, len, offset);

	offset--; /* remove last , */
	size--;
	ret = snprintf(buf + offset, len, " ");
	BUFFER_SIZE(ret, size, len, offset);

	return size;
}

int __snprintf_conntrack_default(char *buf, 
				 unsigned int len,
				 const struct nf_conntrack *ct,
				 unsigned int msg_type,
				 unsigned int flags,
				 struct nfct_labelmap *map)
{
	int ret = 0, size = 0, offset = 0;

	if (flags & NFCT_OF_SHOW_LAYER3) {
		ret = __snprintf_l3protocol(buf+offset, len, ct);
		BUFFER_SIZE(ret, size, len, offset);
	}

	ret = __snprintf_protocol(buf+offset, len, ct);
	BUFFER_SIZE(ret, size, len, offset);
	ret = __snprintf_address(buf+offset, len, &ct->head.orig,
				 "src", "dst");
	BUFFER_SIZE(ret, size, len, offset);

	if (test_bit(ATTR_ORIG_COUNTER_PACKETS, ct->head.set) &&
	    test_bit(ATTR_ORIG_COUNTER_BYTES, ct->head.set)) {
		ret = __snprintf_counters(buf+offset, len, ct, __DIR_ORIG, __DIR_REPL);
		BUFFER_SIZE(ret, size, len, offset);
	}
	/* Delete the last blank space */
	size--;

	return size;
}
