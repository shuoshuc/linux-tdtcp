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

/* TDTCP option bits, each suboption type takes one bit, up to 16. */
#define OPTION_TDTCP_TDC_SYN		BIT(0)
#define OPTION_TDTCP_TDC_SYNACK		BIT(1)
#define OPTION_TDTCP_TD_DA		BIT(2)

/* TDTCP option subtypes */
#define TDTCPOPT_TD_UNKNOWN	0 /* default placeholder subtype goes first */
#define TDTCPOPT_TD_CAPABLE	1
#define TDTCPOPT_TD_DA		2

/* TDTCP option header length for each suboption packet. */
#define TCPOLEN_TDTCP_TDC		4
#define TCPOLEN_TDTCP_TDDA		8

/* Flags used in TDTCP subtype TD_DA, up to 8. */
#define TD_DA_FLG_A 0x01 /* packet contains TDTCP sub ack only */
#define TD_DA_FLG_D 0x02 /* packet contains TDTCP sub data seq only */
#define TD_DA_FLG_B 0x04 /* packet contains both TDTCP sub data seq and ack */

/* Macros to help shorten accessing td_subf members. */
#define TD_UNA(tp, tdn_id) (tp)->td_subf[tdn_id].snd_una
#define TD_NXT(tp, tdn_id) (tp)->td_subf[tdn_id].snd_nxt
#define TD_PREV_UNA(tp, tdn_id) (tp)->td_subf[tdn_id].prev_snd_una
#define TD_PREV_NXT(tp, tdn_id) (tp)->td_subf[tdn_id].prev_snd_nxt
#define TD_CWND(tp, tdn_id) (tp)->td_subf[tdn_id].snd_cwnd
#define TD_PRIOR_CWND(tp, tdn_id) (tp)->td_subf[tdn_id].prior_cwnd
#define TD_SSTHRESH(tp, tdn_id) (tp)->td_subf[tdn_id].snd_ssthresh
#define TD_PRIOR_SSTHRESH(tp, tdn_id) (tp)->td_subf[tdn_id].prior_ssthresh
#define TD_CWND_LIMITED(tp, tdn_id) (tp)->td_subf[tdn_id].is_cwnd_limited
#define TD_CWND_CNT(tp, tdn_id) (tp)->td_subf[tdn_id].snd_cwnd_cnt
#define TD_PKTS_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].packets_out
#define TD_MAX_PKTS_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].max_packets_out
#define TD_MAX_PKTS_SEQ(tp, tdn_id) (tp)->td_subf[tdn_id].max_packets_seq

struct tdtcp_out_options {
#if IS_ENABLED(CONFIG_TDTCP)
	u16 suboptions;		/* a bit mask for TDTCP suboption type. */
	u8 num_tdns;		/* number of TDNs perceived locally. */
	u8 td_da_flags;		/* flags to be set in TD_DA subtype. */
	u8 data_tdn_id;		/* TDN ID to which the carried data belongs. */
	u8 ack_tdn_id;		/* TDN ID to which the suback is crediting. */
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

/* Return the cwnd of current TDN or the default snd_cwnd. */
static inline u32 td_cwnd(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND(tp, tp->curr_tdn_id) : tp->snd_cwnd;
}

/* Assign val to is_cwnd_limited of current TDN or the default variable. */
static inline void set_cwnd(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND(tp, tp->curr_tdn_id) : &tp->snd_cwnd) = val;
}

/* Return is_cwnd_limited of current TDN or the default variable value. */
static inline bool td_cwnd_limited(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_LIMITED(tp, tp->curr_tdn_id) : tp->is_cwnd_limited;
}

/* Assign val to is_cwnd_limited of current TDN or the default variable. */
/* Note: is_cwnd_limited is a bit field, we cannot use the same ptr dereference
 * trick to compactly assign to different variables.
 */
static inline void set_cwnd_limited(struct tcp_sock *tp, bool val)
{
	if (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) {
		TD_CWND_LIMITED(tp, tp->curr_tdn_id) = val;
	} else {
		tp->is_cwnd_limited = val;
	}
}

/* Return is_cwnd_limited of current TDN or the default variable value. */
static inline u32 td_max_pkts_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_MAX_PKTS_OUT(tp, tp->curr_tdn_id) : tp->max_packets_out;
}

/* Assign val to max_packets_out of current TDN or the default variable. */
static inline void set_max_pkts_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_MAX_PKTS_OUT(tp, tp->curr_tdn_id) : &tp->max_packets_out) = val;
}

/* Return max_packets_seq of current TDN or the default variable value. */
static inline u32 td_max_pkts_seq(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_MAX_PKTS_SEQ(tp, tp->curr_tdn_id) : tp->max_packets_seq;
}

/* Assign val to max_packets_seq of current TDN or the default variable. */
static inline void set_max_pkts_seq(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_MAX_PKTS_SEQ(tp, tp->curr_tdn_id) : &tp->max_packets_seq) = val;
}

/* Return packets_out of current TDN or the default variable value. */
static inline u32 td_pkts_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PKTS_OUT(tp, tp->curr_tdn_id) : tp->packets_out;
}

/* Assign val to packets_out of current TDN or the default variable. */
static inline void set_pkts_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PKTS_OUT(tp, tp->curr_tdn_id) : &tp->packets_out) = val;
}

/* Return snd_una of current TDN or the default variable value. */
static inline u32 td_una(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNA(tp, tp->curr_tdn_id) : tp->snd_una;
}

/* Assign val to snd_una of current TDN or the default variable. */
static inline void set_una(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNA(tp, tp->curr_tdn_id) : &tp->snd_una) = val;
}

/* Return snd_nxt of current TDN or the default variable value. */
static inline u32 td_nxt(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_NXT(tp, tp->curr_tdn_id) : tp->snd_nxt;
}

/* Assign val to snd_nxt of current TDN or the default variable. */
static inline void set_nxt(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_NXT(tp, tp->curr_tdn_id) : &tp->snd_nxt) = val;
}

/* Return snd_ssthresh of current TDN or the default variable value. */
static inline u32 td_ssthresh(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_SSTHRESH(tp, tp->curr_tdn_id) : tp->snd_ssthresh;
}

/* Assign val to snd_ssthresh of current TDN or the default variable. */
static inline void set_ssthresh(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_SSTHRESH(tp, tp->curr_tdn_id) : &tp->snd_ssthresh) = val;
}

/* Return prior_cwnd of current TDN or the default variable value. */
static inline u32 td_prior_cwnd(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_CWND(tp, tp->curr_tdn_id) : tp->prior_cwnd;
}

/* Assign val to prior_cwnd of current TDN or the default variable. */
static inline void set_prior_cwnd(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_CWND(tp, tp->curr_tdn_id) : &tp->prior_cwnd) = val;
}

/* Return prior_ssthresh of current TDN or the default variable value. */
static inline u32 td_prior_ssthresh(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_SSTHRESH(tp, tp->curr_tdn_id) : tp->prior_ssthresh;
}

/* Assign val to prior_ssthresh of current TDN or the default variable. */
static inline void set_prior_ssthresh(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_SSTHRESH(tp, tp->curr_tdn_id) : &tp->prior_ssthresh) = val;
}

/* Return snd_cnwd_cnt of current TDN or the default variable value. */
static inline u32 td_cwnd_cnt(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_CNT(tp, tp->curr_tdn_id) : tp->snd_cwnd_cnt;
}

/* Assign val to snd_cwnd_cnt of current TDN or the default variable. */
static inline void set_cwnd_cnt(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_CNT(tp, tp->curr_tdn_id) : &tp->snd_cwnd_cnt) = val;
}

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
