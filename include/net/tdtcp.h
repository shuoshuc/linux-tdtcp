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
#include <linux/workqueue.h>

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

extern u8 global_tdn_id;
#if IS_ENABLED(CONFIG_PER_SOCK_TDN)
static inline u8 GET_TDN(const struct tcp_sock *tp) {
	return READ_ONCE(tp->curr_tdn_id);
}
/* NOTE: This function is *NOT* supposed to be called when PER_SOCK_TDN=y. */
static inline u8 GET_GLOBAL_TDN(void) {
	return 0xFF;
}
static inline void SET_TDN(struct tcp_sock *tp, u8 val) {
	WRITE_ONCE(tp->curr_tdn_id, val);
}
#else
static inline u8 GET_TDN(const struct tcp_sock *tp) {
	return READ_ONCE(tp->curr_tdn_id);
}
/* A debug only helper function that returns the source of truth -
 * global_tdn_id.
 */
static inline u8 GET_GLOBAL_TDN(void) {
	return READ_ONCE(global_tdn_id);
}
static inline void SET_TDN(struct tcp_sock *tp, u8 val) {
	WRITE_ONCE(global_tdn_id, val);
}
/* FLASEW_XXX: same thing as the per socket SET_TDN */
static inline void SET_SOCK_TDN(struct tcp_sock *tp) {
	WRITE_ONCE(tp->curr_tdn_id, READ_ONCE(global_tdn_id));
}
#endif

/* Macros to help shorten accessing sock td_subf members. */
#define TD_PACING_RATE(sk, tdn_id) (sk)->td_subf[tdn_id].sk_pacing_rate

/* Macros to help shorten accessing inet_sock td_subf members. */
#define TD_CA_STATE(icsk, tdn_id) (icsk)->td_subf[tdn_id].ca_state
#define TD_ICSK_REXMITS(icsk, tdn_id) (icsk)->td_subf[tdn_id].icsk_retransmits
#define TD_ICSK_RTO(icsk, tdn_id) (icsk)->td_subf[tdn_id].icsk_rto

/* Macros to help shorten accessing tcp_sock td_subf members. */
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
#define TD_CWND_STAMP(tp, tdn_id) (tp)->td_subf[tdn_id].snd_cwnd_stamp
#define TD_CWND_USED(tp, tdn_id) (tp)->td_subf[tdn_id].snd_cwnd_used
#define TD_PKTS_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].packets_out
#define TD_RETRANS_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].retrans_out
#define TD_LOST_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].lost_out
#define TD_SACKED_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].sacked_out
#define TD_MAX_PKTS_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].max_packets_out
#define TD_MAX_PKTS_SEQ(tp, tdn_id) (tp)->td_subf[tdn_id].max_packets_seq
#define TD_PRR_DELIVERED(tp, tdn_id) (tp)->td_subf[tdn_id].prr_delivered
#define TD_PRR_OUT(tp, tdn_id) (tp)->td_subf[tdn_id].prr_out
#define TD_DELIVERED(tp, tdn_id) (tp)->td_subf[tdn_id].delivered
#define TD_UNDO_RETRANS(tp, tdn_id) (tp)->td_subf[tdn_id].undo_retrans
#define TD_RETRANS_STAMP(tp, tdn_id) (tp)->td_subf[tdn_id].retrans_stamp
#define TD_REORDERING(tp, tdn_id) (tp)->td_subf[tdn_id].reordering
#define TD_HIGH_SEQ(tp, tdn_id) (tp)->td_subf[tdn_id].high_seq
#define TD_UNDO_MARKER(tp, tdn_id) (tp)->td_subf[tdn_id].undo_marker

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

/* Populates SKB CB with TDDA FLG_D metadata. */
void tdtcp_set_skb_tdda(const struct sk_buff *skb, const struct sock *sk,
			u8 flags);

/* Return sk_pacing_rate of current TDN or the default variable value. */
static inline unsigned long td_pacing_rate(const struct sock *sk)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PACING_RATE(sk, GET_TDN(tcp_sk(sk))) : sk->sk_pacing_rate;
}

/* Return sk_pacing_rate of given TDN or the default variable value. */
static inline unsigned long td_get_pacing_rate(const struct sock *sk, u8 tdn_id)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PACING_RATE(sk, tdn_id) : sk->sk_pacing_rate;
}

/* Assign val to sk_pacing_rate of current TDN or the default variable.
 * Note that sk_pacing_rate is shared between FQ qdisc and TCP stack,
 * so we use WRITE_ONCE to get rid of potential cache.
 */
static inline void set_pacing_rate(struct sock *sk, unsigned long val)
{
	WRITE_ONCE(*((tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		     &TD_PACING_RATE(sk, GET_TDN(tcp_sk(sk))) :
		     &sk->sk_pacing_rate), val);
}

/* Assign val to sk_pacing_rate of given TDN or the default variable.
 * Note that sk_pacing_rate is shared between FQ qdisc and TCP stack,
 * so we use WRITE_ONCE to get rid of potential cache.
 */
static inline void td_set_pacing_rate(struct sock *sk, unsigned long val,
				      u8 tdn_id)
{
	WRITE_ONCE(*((tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		     &TD_PACING_RATE(sk, tdn_id) : &sk->sk_pacing_rate), val);
}

/* Return ca_state of current TDN or the default variable value. */
static inline u8 td_ca_state(const struct sock *sk)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CA_STATE(inet_csk(sk), GET_TDN(tcp_sk(sk))) :
		inet_csk(sk)->icsk_ca_state;
}

/* Return ca_state of given TDN or the default variable value. */
static inline u8 td_get_ca_state(const struct sock *sk, u8 tdn_id)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CA_STATE(inet_csk(sk), tdn_id) : inet_csk(sk)->icsk_ca_state;
}

/* Assign val to ca_state of current TDN or the default variable. */
/* Note: icsk_ca_state is a bit field, we cannot use the same ptr dereference
 * trick to compactly assign to different variables.
 */
static inline void set_ca_state(struct sock *sk, u8 val)
{
	if (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) {
		TD_CA_STATE(inet_csk(sk), GET_TDN(tcp_sk(sk))) = val;
	} else {
		inet_csk(sk)->icsk_ca_state = val;
	}
}

/* Assign val to ca_state of given TDN or the default variable. */
/* Note: icsk_ca_state is a bit field, we cannot use the same ptr dereference
 * trick to compactly assign to different variables.
 */
static inline void td_set_ca_state(struct sock *sk, u8 val, u8 tdn_id)
{
	if (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) {
		TD_CA_STATE(inet_csk(sk), tdn_id) = val;
	} else {
		inet_csk(sk)->icsk_ca_state = val;
	}
}

/* Return icsk_retransmits of current TDN or the default variable value. */
static inline u8 td_icsk_rexmits(const struct sock *sk)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_ICSK_REXMITS(inet_csk(sk), GET_TDN(tcp_sk(sk))) :
		inet_csk(sk)->icsk_retransmits;
}

/* Assign val to icsk_retransmits of current TDN or the default variable. */
static inline void set_icsk_rexmits(const struct sock *sk, u8 val)
{
	*((tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_ICSK_REXMITS(inet_csk(sk), GET_TDN(tcp_sk(sk))) :
		&inet_csk(sk)->icsk_retransmits) = val;
}

/* Return icsk_rto of current TDN or the default variable value. */
static inline u32 td_icsk_rto(const struct sock *sk)
{
	return (tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_ICSK_RTO(inet_csk(sk), GET_TDN(tcp_sk(sk))) :
		inet_csk(sk)->icsk_rto;
}

/* Assign val to icsk_rto of current TDN or the default variable. */
static inline void set_icsk_rto(const struct sock *sk, u32 val)
{
	*((tcp_sk(sk)->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_ICSK_RTO(inet_csk(sk), GET_TDN(tcp_sk(sk))) :
		&inet_csk(sk)->icsk_rto) = val;
}

/* Return the cwnd of current TDN or the default snd_cwnd. */
static inline u32 td_cwnd(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND(tp, GET_TDN(tp)) : tp->snd_cwnd;
}

/* Return the cwnd of given TDN or the default snd_cwnd. */
static inline u32 td_get_cwnd(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND(tp, tdn_id) : tp->snd_cwnd;
}

/* Assign val to cwnd of current TDN or the default variable. */
static inline void set_cwnd(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND(tp, GET_TDN(tp)) : &tp->snd_cwnd) = val;
}

/* Assign val to cwnd of given TDN or the default variable. */
static inline void td_set_cwnd(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND(tp, tdn_id) : &tp->snd_cwnd) = val;
}

/* Return is_cwnd_limited of current TDN or the default variable value. */
static inline bool td_cwnd_limited(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_LIMITED(tp, GET_TDN(tp)) : tp->is_cwnd_limited;
}

/* Return is_cwnd_limited of given TDN or the default variable value. */
static inline bool td_get_cwnd_limited(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_LIMITED(tp, tdn_id) : tp->is_cwnd_limited;
}

/* Assign val to is_cwnd_limited of current TDN or the default variable. */
/* Note: is_cwnd_limited is a bit field, we cannot use the same ptr dereference
 * trick to compactly assign to different variables.
 */
static inline void set_cwnd_limited(struct tcp_sock *tp, bool val)
{
	if (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) {
		TD_CWND_LIMITED(tp, GET_TDN(tp)) = val;
	} else {
		tp->is_cwnd_limited = val;
	}
}

/* Return is_cwnd_limited of current TDN or the default variable value. */
static inline u32 td_max_pkts_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_MAX_PKTS_OUT(tp, GET_TDN(tp)) : tp->max_packets_out;
}

/* Return is_cwnd_limited of given TDN or the default variable value. */
static inline u32 td_get_max_pkts_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_MAX_PKTS_OUT(tp, tdn_id) : tp->max_packets_out;
}

/* Assign val to max_packets_out of current TDN or the default variable. */
static inline void set_max_pkts_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_MAX_PKTS_OUT(tp, GET_TDN(tp)) : &tp->max_packets_out) = val;
}

/* Assign val to max_packets_out of given TDN or the default variable. */
static inline void td_set_max_pkts_out(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_MAX_PKTS_OUT(tp, tdn_id) : &tp->max_packets_out) = val;
}

/* Return max_packets_seq of current TDN or the default variable value. */
static inline u32 td_max_pkts_seq(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_MAX_PKTS_SEQ(tp, GET_TDN(tp)) : tp->max_packets_seq;
}

/* Assign val to max_packets_seq of current TDN or the default variable. */
static inline void set_max_pkts_seq(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_MAX_PKTS_SEQ(tp, GET_TDN(tp)) : &tp->max_packets_seq) = val;
}

/* Return packets_out of current TDN or the default variable value. */
static inline u32 td_pkts_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PKTS_OUT(tp, GET_TDN(tp)) : tp->packets_out;
}

/* Return packets_out of given TDN or the default variable value. */
static inline u32 td_get_pkts_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PKTS_OUT(tp, tdn_id) : tp->packets_out;
}

/* Assign val to packets_out of current TDN or the default variable. */
static inline void set_pkts_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PKTS_OUT(tp, GET_TDN(tp)) : &tp->packets_out) = val;
}

/* Assign val to packets_out of given TDN or the default variable. */
static inline void td_set_pkts_out(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PKTS_OUT(tp, tdn_id) : &tp->packets_out) = val;
}

/* Return snd_una of current TDN or the default variable value. */
static inline u32 td_una(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNA(tp, GET_TDN(tp)) : tp->snd_una;
}

/* Assign val to snd_una of current TDN or the default variable. */
static inline void set_una(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNA(tp, GET_TDN(tp)) : &tp->snd_una) = val;
}

/* Return snd_nxt of current TDN or the default variable value. */
static inline u32 td_nxt(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_NXT(tp, GET_TDN(tp)) : tp->snd_nxt;
}

/* Assign val to snd_nxt of current TDN or the default variable. */
static inline void set_nxt(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_NXT(tp, GET_TDN(tp)) : &tp->snd_nxt) = val;
}

/* Return snd_ssthresh of current TDN or the default variable value. */
static inline u32 td_ssthresh(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_SSTHRESH(tp, GET_TDN(tp)) : tp->snd_ssthresh;
}

/* Return snd_ssthresh of given TDN or the default variable value. */
static inline u32 td_get_ssthresh(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_SSTHRESH(tp, tdn_id) : tp->snd_ssthresh;
}

/* Assign val to snd_ssthresh of current TDN or the default variable. */
static inline void set_ssthresh(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_SSTHRESH(tp, GET_TDN(tp)) : &tp->snd_ssthresh) = val;
}

/* Assign val to snd_ssthresh of given TDN or the default variable. */
static inline void td_set_ssthresh(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_SSTHRESH(tp, tdn_id) : &tp->snd_ssthresh) = val;
}

/* Return prior_cwnd of current TDN or the default variable value. */
static inline u32 td_prior_cwnd(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_CWND(tp, GET_TDN(tp)) : tp->prior_cwnd;
}

/* Return prior_cwnd of given TDN or the default variable value. */
static inline u32 td_get_prior_cwnd(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_CWND(tp, tdn_id) : tp->prior_cwnd;
}

/* Assign val to prior_cwnd of current TDN or the default variable. */
static inline void set_prior_cwnd(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_CWND(tp, GET_TDN(tp)) : &tp->prior_cwnd) = val;
}

/* Assign val to prior_cwnd of given TDN or the default variable. */
static inline void td_set_prior_cwnd(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_CWND(tp, tdn_id) : &tp->prior_cwnd) = val;
}

/* Return prior_ssthresh of current TDN or the default variable value. */
static inline u32 td_prior_ssthresh(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_SSTHRESH(tp, GET_TDN(tp)) : tp->prior_ssthresh;
}

/* Return prior_ssthresh of given TDN or the default variable value. */
static inline u32 td_get_prior_ssthresh(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRIOR_SSTHRESH(tp, tdn_id) : tp->prior_ssthresh;
}

/* Assign val to prior_ssthresh of current TDN or the default variable. */
static inline void set_prior_ssthresh(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_SSTHRESH(tp, GET_TDN(tp)) : &tp->prior_ssthresh) = val;
}

/* Assign val to prior_ssthresh of given TDN or the default variable. */
static inline void td_set_prior_ssthresh(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRIOR_SSTHRESH(tp, tdn_id) : &tp->prior_ssthresh) = val;
}

/* Return snd_cnwd_cnt of current TDN or the default variable value. */
static inline u32 td_cwnd_cnt(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_CNT(tp, GET_TDN(tp)) : tp->snd_cwnd_cnt;
}

/* Return snd_cnwd_cnt of given TDN or the default variable value. */
static inline u32 td_get_cwnd_cnt(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_CNT(tp, tdn_id) : tp->snd_cwnd_cnt;
}

/* Assign val to snd_cwnd_cnt of current TDN or the default variable. */
static inline void set_cwnd_cnt(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_CNT(tp, GET_TDN(tp)) : &tp->snd_cwnd_cnt) = val;
}

/* Assign val to snd_cwnd_cnt of given TDN or the default variable. */
static inline void td_set_cwnd_cnt(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_CNT(tp, tdn_id) : &tp->snd_cwnd_cnt) = val;
}

/* Return snd_cnwd_stamp of current TDN or the default variable value. */
static inline u32 td_cwnd_stamp(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_STAMP(tp, GET_TDN(tp)) : tp->snd_cwnd_stamp;
}

/* Return snd_cnwd_stamp of given TDN or the default variable value. */
static inline u32 td_get_cwnd_stamp(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_STAMP(tp, tdn_id) : tp->snd_cwnd_stamp;
}

/* Assign val to snd_cwnd_stamp of current TDN or the default variable. */
static inline void set_cwnd_stamp(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_STAMP(tp, GET_TDN(tp)) : &tp->snd_cwnd_stamp) = val;
}

/* Assign val to snd_cwnd_stamp of given TDN or the default variable. */
static inline void td_set_cwnd_stamp(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_STAMP(tp, tdn_id) : &tp->snd_cwnd_stamp) = val;
}

/* Return snd_cnwd_used of current TDN or the default variable value. */
static inline u32 td_cwnd_used(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_CWND_USED(tp, GET_TDN(tp)) : tp->snd_cwnd_used;
}

/* Assign val to snd_cwnd_used of current TDN or the default variable. */
static inline void set_cwnd_used(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_CWND_USED(tp, GET_TDN(tp)) : &tp->snd_cwnd_used) = val;
}

/* Return retrans_out of current TDN or the default variable value. */
static inline u32 td_retrans_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_RETRANS_OUT(tp, GET_TDN(tp)) : tp->retrans_out;
}

/* Return retrans_out of given TDN or the default variable value. */
static inline u32 td_get_retrans_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_RETRANS_OUT(tp, tdn_id) : tp->retrans_out;
}

/* Assign val to retrans_out of current TDN or the default variable. */
static inline void set_retrans_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_RETRANS_OUT(tp, GET_TDN(tp)) : &tp->retrans_out) = val;
}

/* Assign val to retrans_out of given TDN or the default variable. */
static inline void td_set_retrans_out(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_RETRANS_OUT(tp, tdn_id) : &tp->retrans_out) = val;
}

/* Return lost_out of current TDN or the default variable value. */
static inline u32 td_lost_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_LOST_OUT(tp, GET_TDN(tp)) : tp->lost_out;
}

/* Return lost_out of given TDN or the default variable value. */
static inline u32 td_get_lost_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_LOST_OUT(tp, tdn_id) : tp->lost_out;
}

/* Assign val to lost_out of current TDN or the default variable. */
static inline void set_lost_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_LOST_OUT(tp, GET_TDN(tp)) : &tp->lost_out) = val;
}

/* Assign val to lost_out of given TDN or the default variable. */
static inline void td_set_lost_out(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_LOST_OUT(tp, tdn_id) : &tp->lost_out) = val;
}

/* Return sacked_out of current TDN or the default variable value. */
static inline u32 td_sacked_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_SACKED_OUT(tp, GET_TDN(tp)) : tp->sacked_out;
}

/* Return sacked_out of given TDN or the default variable value. */
static inline u32 td_get_sacked_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_SACKED_OUT(tp, tdn_id) : tp->sacked_out;
}

/* Assign val to sacked_out of current TDN or the default variable. */
static inline void set_sacked_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_SACKED_OUT(tp, GET_TDN(tp)) : &tp->sacked_out) = val;
}

/* Assign val to sacked_out of given TDN or the default variable. */
static inline void td_set_sacked_out(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_SACKED_OUT(tp, tdn_id) : &tp->sacked_out) = val;
}

/* Return prr_delivered of current TDN or the default variable value. */
static inline u32 td_prr_delivered(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRR_DELIVERED(tp, GET_TDN(tp)) : tp->prr_delivered;
}

/* Return prr_delivered of given TDN or the default variable value. */
static inline u32 td_get_prr_delivered(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRR_DELIVERED(tp, tdn_id) : tp->prr_delivered;
}

/* Assign val to prr_delivered of current TDN or the default variable. */
static inline void set_prr_delivered(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRR_DELIVERED(tp, GET_TDN(tp)) : &tp->prr_delivered) = val;
}

/* Assign val to prr_delivered of given TDN or the default variable. */
static inline void td_set_prr_delivered(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRR_DELIVERED(tp, tdn_id) : &tp->prr_delivered) = val;
}

/* Return prr_out of current TDN or the default variable value. */
static inline u32 td_prr_out(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRR_OUT(tp, GET_TDN(tp)) : tp->prr_out;
}

/* Return prr_out of given TDN or the default variable value. */
static inline u32 td_get_prr_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_PRR_OUT(tp, tdn_id) : tp->prr_out;
}

/* Assign val to prr_out of current TDN or the default variable. */
static inline void set_prr_out(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRR_OUT(tp, GET_TDN(tp)) : &tp->prr_out) = val;
}

/* Assign val to prr_out of given TDN or the default variable. */
static inline void td_set_prr_out(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_PRR_OUT(tp, tdn_id) : &tp->prr_out) = val;
}

/* Return delivered of current TDN or the default variable value. */
static inline u32 td_delivered(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_DELIVERED(tp, GET_TDN(tp)) : tp->delivered;
}

/* Return delivered of given TDN or the default variable value. */
static inline u32 td_get_delivered(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_DELIVERED(tp, tdn_id) : tp->delivered;
}

/* Assign val to delivered of current TDN or the default variable. */
static inline void set_delivered(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_DELIVERED(tp, GET_TDN(tp)) : &tp->delivered) = val;
}

/* Assign val to delivered of given TDN or the default variable. */
static inline void td_set_delivered(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_DELIVERED(tp, tdn_id) : &tp->delivered) = val;
}

/* Return undo_retrans of current TDN or the default variable value. */
static inline int td_undo_retrans(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNDO_RETRANS(tp, GET_TDN(tp)) : tp->undo_retrans;
}

/* Return undo_retrans of given TDN or the default variable value. */
static inline int td_get_undo_retrans(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNDO_RETRANS(tp, tdn_id) : tp->undo_retrans;
}

/* Assign val to undo_retrans of current TDN or the default variable. */
static inline void set_undo_retrans(struct tcp_sock *tp, int val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNDO_RETRANS(tp, GET_TDN(tp)) : &tp->undo_retrans) = val;
}

/* Assign val to undo_retrans of given TDN or the default variable. */
static inline void td_set_undo_retrans(struct tcp_sock *tp, u8 tdn_id, int val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNDO_RETRANS(tp, tdn_id) : &tp->undo_retrans) = val;
}

/* Return retrans_stamp of current TDN or the default variable value. */
static inline u32 td_retrans_stamp(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_RETRANS_STAMP(tp, GET_TDN(tp)) : tp->retrans_stamp;
}

/* Assign val to retrans_stamp of current TDN or the default variable. */
static inline void set_retrans_stamp(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_RETRANS_STAMP(tp, GET_TDN(tp)) : &tp->retrans_stamp) = val;
}

/* Return reordering of current TDN or the default variable value. */
static inline u32 td_reordering(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_REORDERING(tp, GET_TDN(tp)) : tp->reordering;
}

/* Return reordering of given TDN or the default variable value. */
static inline u32 td_get_reordering(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_REORDERING(tp, tdn_id) : tp->reordering;
}

/* Assign val to reordering of current TDN or the default variable. */
static inline void set_reordering(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_REORDERING(tp, GET_TDN(tp)) : &tp->reordering) = val;
}

/* Assign val to reordering of given TDN or the default variable. */
static inline void td_set_reordering(struct tcp_sock *tp, u32 val, u8 tdn_id)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_REORDERING(tp, tdn_id) : &tp->reordering) = val;
}

/* Return high_seq of current TDN or the default variable value. */
static inline u32 td_high_seq(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_HIGH_SEQ(tp, GET_TDN(tp)) : tp->high_seq;
}

/* Return high_seq of given TDN or the default variable value. */
static inline u32 td_get_high_seq(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_HIGH_SEQ(tp, tdn_id) : tp->high_seq;
}

/* Assign val to high_seq of current TDN or the default variable. */
static inline void set_high_seq(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_HIGH_SEQ(tp, GET_TDN(tp)) : &tp->high_seq) = val;
}

/* Assign val to high_seq of given TDN or the default variable. */
static inline void td_set_high_seq(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_HIGH_SEQ(tp, tdn_id) : &tp->high_seq) = val;
}

/* Return undo_marker of current TDN or the default variable value. */
static inline u32 td_undo_marker(const struct tcp_sock *tp)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNDO_MARKER(tp, GET_TDN(tp)) : tp->undo_marker;
}

/* Return undo_marker of given TDN or the default variable value. */
static inline u32 td_get_undo_marker(const struct tcp_sock *tp, u8 tdn_id)
{
	return (tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		TD_UNDO_MARKER(tp, tdn_id) : tp->undo_marker;
}

/* Assign val to undo_marker of current TDN or the default variable. */
static inline void set_undo_marker(struct tcp_sock *tp, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNDO_MARKER(tp, GET_TDN(tp)) : &tp->undo_marker) = val;
}

/* Assign val to undo_marker of given TDN or the default variable. */
static inline void td_set_undo_marker(struct tcp_sock *tp, u8 tdn_id, u32 val)
{
	*((tp->is_tdtcp && IS_ENABLED(CONFIG_TDTCP_DEV)) ?
		&TD_UNDO_MARKER(tp, tdn_id) : &tp->undo_marker) = val;
}

/* TDTCP version of tcp_in_cwnd_reduction(). Check CA state of given TDN instead
 * of the current TDN.
 */
static inline bool tdtcp_in_cwnd_reduction(const struct sock *sk, u8 tdn_id)
{
	return (TCPF_CA_CWR | TCPF_CA_Recovery) &
	       (1 << td_get_ca_state(sk, tdn_id));
}

static inline unsigned int tdtcp_left_out(const struct tcp_sock *tp, u8 tdn_id)
{
	return td_get_sacked_out(tp, tdn_id) + td_get_lost_out(tp, tdn_id);
}

static inline unsigned int tdtcp_packets_in_flight(const struct tcp_sock *tp,
						   u8 tdn_id)
{
	return td_get_pkts_out(tp, tdn_id) - tdtcp_left_out(tp, tdn_id) +
		td_get_retrans_out(tp, tdn_id);
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

struct tdn_work_data {
	struct work_struct	tdn_work;
	struct sock		*sk;
	u8			tdn_id;
};

void tdn_update_handler(struct work_struct *work);

#endif /* __NET_TDTCP_H */
