/* SPDX-License-Identifier: GPL-2.0 */
/* TDTCP options header implementation and helpers.
 *
 * Shawn Chen <shuoshuc@cs.cmu.edu>
 * Carnegie Mellon University 2020.
 */

#include <linux/kernel.h>
#include <net/tdtcp.h>
#include <net/tcp.h>

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
	struct tcp_sock *tp;
	u8 flags = 0;
	tp = tcp_sk(sk);

	/* If skb is null, that indicates caller is just trying to estimate the
	 * option header length but not really constructing the packet. Very
	 * likely that tcp_current_mss() is calling this function. In which
	 * case, we need to give a worst case estimate so that estimate MSS is
	 * large enough. Regardless, TDDA is the only subtype (with a fixed
	 * header size) used in ESTABLISHED state.
	 */
	if (!skb) {
		opts->suboptions = OPTION_TDTCP_TD_DA;
		*size = TCPOLEN_TDTCP_TDDA;
		return true;
	}
	flags = TCP_SKB_CB(skb)->tdtcp_flags;

	/* Initialize opt fields. tdn_id=0 is valid so default to 0xFF. */
	opts->suboptions = 0;
	opts->data_tdn_id = opts->ack_tdn_id = 0xFF;
	opts->subseq = opts->suback = 0;
	opts->td_da_flags = 0;

	/* Prepare data/ack exchange packet headers. No need to process the 3rd
	 * ACK in 3-way handshake since it does not contain TDTCP option header.
	 * Only normal data/ack SKBs will have tdtcp_flags set and there should
	 * be exactly one flag set. (Checked via is_power_of_2 algorithm.)
	 */
	if (flags && !(flags & (flags - 1))) {
		/* If flags in CB is non-zero, it is a TD_DA packet. */
		opts->suboptions = OPTION_TDTCP_TD_DA;
		*size = TCPOLEN_TDTCP_TDDA;
		opts->td_da_flags = flags;

		if (flags & (TD_DA_FLG_B | TD_DA_FLG_D)) {
			opts->data_tdn_id = TCP_SKB_CB(skb)->data_tdn_id;
			opts->subseq = TCP_SKB_CB(skb)->subseq;
		}
		if (flags & (TD_DA_FLG_B | TD_DA_FLG_A)) {
			opts->ack_tdn_id = TCP_SKB_CB(skb)->ack_tdn_id;
			opts->suback = TCP_SKB_CB(skb)->suback;
		}
		ret = true;
	} else {
		/* If no flag is set at all, it could possibly be a handshake
		 * ACK packet, which is not illegal.
		 */
		pr_debug("tdtcp_established_options() illegal TD_DA flags: "
			 "B=%u D=%u A=%u.", flags & TD_DA_FLG_B,
			 flags & TD_DA_FLG_D, flags & TD_DA_FLG_A);
		ret = false;
	}

	/* we reserved enough space for the above options, and exceeding the
	 * TCP option space would be fatal
	 */
	if (WARN_ON_ONCE(*size > remaining))
		return false;

	remaining -= *size;
	return ret;
}

void tdtcp_write_options(__be32 *ptr, struct tdtcp_out_options *opts)
{
	u8 len;

	if ((OPTION_TDTCP_TDC_SYN | OPTION_TDTCP_TDC_SYNACK) &
	    opts->suboptions) {
		pr_debug("tdtcp_write_options(): construct TD_CAPABLE handshake "
			 "header, TDC_SYN=%lu, TDC_SYNACK=%lu.",
			 OPTION_TDTCP_TDC_SYN & opts->suboptions,
			 OPTION_TDTCP_TDC_SYNACK & opts->suboptions);

		len = TCPOLEN_TDTCP_TDC;

		/* Populates the first 4 bytes of the TDTCP option header. */
		*ptr++ = tdtcp_option(TDTCPOPT_TD_CAPABLE, len, opts->num_tdns);
	}

	if (OPTION_TDTCP_TD_DA & opts->suboptions) {
		pr_debug("tdtcp_write_options(): construct TD_DA header, "
			 "Flags B=%u D=%u A=%u, data_tdn_id=%u, ack_tdn_id=%u, "
			 "subseq=%u, suback=%u.",
			 TD_DA_FLG_B & opts->td_da_flags,
			 TD_DA_FLG_D & opts->td_da_flags,
			 TD_DA_FLG_A & opts->td_da_flags,
			 opts->data_tdn_id, opts->ack_tdn_id,
			 opts->subseq, opts->suback);

		len = TCPOLEN_TDTCP_TDDA;

		/* Populates the first 4 bytes of the TDTCP option header. */
		*ptr++ = tdtcp_option(TDTCPOPT_TD_DA, len, opts->td_da_flags);
		*ptr++ = htonl((opts->data_tdn_id << 24) | (0x0 << 16) |
			       (opts->ack_tdn_id << 8) | 0x0);
		*ptr++ = htonl(opts->subseq);
		*ptr++ = htonl(opts->suback);
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
