/* SPDX-License-Identifier: GPL-2.0 */
/* TDTCP options header implementation and helpers.
 *
 * Shawn Chen <shuoshuc@cs.cmu.edu>
 * Carnegie Mellon University 2020.
 */

#include <linux/kernel.h>
#include <net/tdtcp.h>
#include <net/tcp.h>
#include "options.h"

/* A helper function to pack bits into the option header.
 * Returns a 32-bit packed data entry in network endianess that is ready to go
 * onto the wire.
 *
 * Since this helper specifically constructs TDTCP option header, the highest
 * byte is always kind=TDTCP. The 2nd byte is option header length depending on
 * which subtype message is used. The higher 4 bits of the third byte is the
 * suboption type, e.g., TD_CAPABLE. The lower 4 bits should always be 0. The
 * lowest byte is for various flags or other fields.
 */
static inline __be32 tdtcp_option(u8 subopt, u8 len, u8 field)
{
	return htonl((TCPOPT_TDTCP << 24) | (len << 16) | (subopt << 12) |
		     (0x0 << 8) | field);
}

bool tdtcp_syn_options(unsigned int *size, struct tdtcp_out_options *opts)
{
	pr_debug("tdtcp_syn_options() invoked for TDC_SYN.");
	opts->suboptions = OPTION_TDTCP_TDC_SYN;
	opts->num_tdns = TDTCP_NUM_TDNS;
	*size = TCPOLEN_TDTCP_TDC;

	return true;
}

bool tdtcp_synack_options(unsigned int *size, struct tdtcp_out_options *opts)
{
	pr_debug("tdtcp_synack_options() invoked for TDC_SYNACK.");
	opts->suboptions = OPTION_TDTCP_TDC_SYNACK;
	opts->num_tdns = TDTCP_NUM_TDNS;
	*size = TCPOLEN_TDTCP_TDC;

	return true;
}

bool tdtcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct tdtcp_out_options *opts)
{
	bool ret = false;
	unsigned int opt_size = 0;
	struct tcp_sock *tp;

	opts->suboptions = 0;
	tp = tcp_sk(sk);

	/* TODO: processing for data/ack exchange. No need to process the 3rd
	 * ACK since it does not contain TDTCP option header.
	 */

	/* we reserved enough space for the above options, and exceeding the
	 * TCP option space would be fatal
	 */
	if (WARN_ON_ONCE(opt_size > remaining))
		return false;

	*size += opt_size;
	remaining -= opt_size;
	return ret;
}

void tdtcp_write_options(__be32 *ptr, struct tdtcp_out_options *opts)
{
	if ((OPTION_TDTCP_TDC_SYN | OPTION_TDTCP_TDC_SYNACK) &
	    opts->suboptions) {
		u8 len;

		pr_debug("tdtcp_write_options(): construct TD_CAPABLE handshake "
			 "header, TDC_SYN=%lu, TDC_SYNACK=%lu.",
			 OPTION_TDTCP_TDC_SYN & opts->suboptions,
			 OPTION_TDTCP_TDC_SYNACK & opts->suboptions);

		len = TCPOLEN_TDTCP_TDC;

		/* Populates the first 4 bytes of the TDTCP option header. */
		*ptr++ = tdtcp_option(TDTCPOPT_TD_CAPABLE, len, opts->num_tdns);
	}

	if (OPTION_TDTCP_TD_DA & opts->suboptions) {
		/* TODO: data/ack option header TBD. */
	}
}

void tdtcp_parse_options(const struct tcphdr *th, const unsigned char *ptr,
			 int opsize, int estab,
			 struct tcp_options_received *opt_rx)
{
	bool is_syn = th->syn && !th->ack;
	bool is_synack = th->syn && th->ack;

	/* Parses the handshake packets, i.e., TD_CAPABLE. */
	if ((opsize == TCPOLEN_TDTCP_TDC) && !estab && (is_syn || is_synack)) {
		opt_rx->tdtcp_ok = (*ptr++ >> 4) == TDTCPOPT_TD_CAPABLE;
		if (opt_rx->tdtcp_ok) {
			opt_rx->num_tdns = *(u8 *)ptr;
		}
		pr_debug("TDTCP subtype=TDC_(SYN|SYNACK), peer tdtcp_ok=%u, "
			 "num_tdns=%u.", opt_rx->tdtcp_ok, opt_rx->num_tdns);
	}
}
