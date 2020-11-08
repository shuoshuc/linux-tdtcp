/* SPDX-License-Identifier: GPL-2.0 */
/* TDTCP options header struct and helper functions.
 *
 * Shawn Chen <shuoshuc@cs.cmu.edu>
 * Carnegie Mellon University 2020.
 */

#ifndef __NET_TDTCP_H
#define __NET_TDTCP_H

#include <linux/kconfig.h>
#include <linux/types.h>
#include <linux/tcp.h>

/* Hard codes # TDNs to be 2. It needs to be properly received from the ToR via
 * a control message.
 */
#define TDTCP_NUM_TDNS 2

struct tdtcp_out_options {
#if IS_ENABLED(CONFIG_TDTCP)
	u16 suboptions;		/* a bit mask for TDTCP suboption type. */
	u8 num_tdns;		/* number of TDNs perceived locally. */
#endif
};

/* Default function behavior is defined in else-branch when TDTCP is not
 * supported/enabled.
 */
#ifdef CONFIG_TDTCP

static inline bool sk_is_tdtcp(const struct sock *sk)
{
	return tcp_sk(sk)->is_tdtcp;
}

/* Returns whether the request_sock is TDTCP enabled. */
static inline bool rsk_is_tdtcp(const struct request_sock *req)
{
	return tcp_rsk(req)->is_tdtcp;
}

/* Returns true if opts is populated with SYN options, otherwise false. */
bool tdtcp_syn_options(unsigned int *size, struct tdtcp_out_options *opts);

/* Returns true if opts is populated with SYNACK options, otherwise false. */
bool tdtcp_synack_options(unsigned int *size, struct tdtcp_out_options *opts);

/* Returns true if opts is populated with correct estbalished state options. */
bool tdtcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct tdtcp_out_options *opts);

/* Write option into packet (pointed by ptr). This function should only be
 * called when CONFIG_TDTCP=y, so there is no default fallback implementation
 * for the disabled world.
 */
void tdtcp_write_options(__be32 *ptr, struct tdtcp_out_options *opts);

/* Option header parser for various suboption types. */
void tdtcp_parse_options(const struct tcphdr *th, const unsigned char *ptr,
			 int opsize, int estab,
			 struct tcp_options_received *opt_rx);

#else

static inline bool sk_is_tdtcp(const struct sock *sk)
{
	return false;
}

static inline bool rsk_is_tdtcp(const struct request_sock *req)
{
	return false;
}

static inline bool tdtcp_syn_options(unsigned int *size,
				     struct tdtcp_out_options *opts)
{
	return false;
}

static inline bool tdtcp_synack_options(unsigned int *size,
					struct tdtcp_out_options *opts)
{
	return false;
}

static inline bool tdtcp_established_options(struct sock *sk,
					     struct sk_buff *skb,
					     unsigned int *size,
					     unsigned int remaining,
					     struct tdtcp_out_options *opts)
{
	return false;
}

#endif /* CONFIG_TDTCP */

#endif /* __NET_TDTCP_H */
