// SPDX-License-Identifier: GPL-2.0-only
/*
 * A TCP Reno implementation customized for TDTCP.
 */

#include <net/tcp.h>

/* Slow start is used when congestion window is no greater than the slow start
 * threshold. We base on RFC2581 and also handle stretch ACKs properly.
 * We do not implement RFC3465 Appropriate Byte Counting (ABC) per se but
 * something better;) a packet is only considered (s)acked in its entirety to
 * defend the ACK attacks described in the RFC. Slow start processes a stretch
 * ACK of degree N as if N acks of degree 1 are received back to back except
 * ABC caps N to 2. Slow start exits when cwnd grows over ssthresh and
 * returns the leftover acks to adjust cwnd in congestion avoidance mode.
 */
static u32 tdtcp_slow_start(struct tcp_sock *tp, u32 acked, u8 tdn_id)
{
	u32 cwnd = min(td_get_cwnd(tp, tdn_id) + acked,
		       td_get_ssthresh(tp, tdn_id));

	acked -= cwnd - td_get_cwnd(tp, tdn_id);
	td_set_cwnd(tp, min(cwnd, tp->snd_cwnd_clamp), tdn_id);

	return acked;
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
static void tdtcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked, u8 tdn_id)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (td_get_cwnd_cnt(tp, tdn_id) >= w) {
		td_set_cwnd_cnt(tp, 0, tdn_id);
		td_set_cwnd(tp, td_get_cwnd(tp, tdn_id) + 1, tdn_id);
	}

	td_set_cwnd_cnt(tp, td_get_cwnd_cnt(tp, tdn_id) + acked, tdn_id);
	if (td_get_cwnd_cnt(tp, tdn_id) >= w) {
		u32 delta = td_get_cwnd_cnt(tp, tdn_id) / w;

		td_set_cwnd_cnt(tp, td_get_cwnd_cnt(tp, tdn_id) - delta * w,
				tdn_id);
		td_set_cwnd(tp, td_get_cwnd(tp, tdn_id) + delta, tdn_id);
	}
	td_set_cwnd(tp, min(td_get_cwnd(tp, tdn_id), tp->snd_cwnd_clamp), tdn_id);
}

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
static void tdtcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked, u8 tdn_id)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk, tdn_id))
		return;

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp, tdn_id)) {
		acked = tdtcp_slow_start(tp, acked, tdn_id);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tdtcp_cong_avoid_ai(tp, td_get_cwnd(tp, tdn_id), acked, tdn_id);
}

/* Slow start threshold is half the congestion window (min 2) */
static u32 tdtcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(td_cwnd(tp) >> 1U, 2U);
}

static u32 tdtcp_reno_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(td_cwnd(tp), td_prior_cwnd(tp));
}

static struct tcp_congestion_ops tdtcp_reno __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "tdtcp_reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tdtcp_reno_ssthresh,
	.cong_avoid	= tdtcp_reno_cong_avoid,
	.undo_cwnd	= tdtcp_reno_undo_cwnd,
};

static int __init tdtcp_reno_register(void)
{
	return tcp_register_congestion_control(&tdtcp_reno);
}

static void __exit tdtcp_reno_unregister(void)
{
	tcp_unregister_congestion_control(&tdtcp_reno);
}

module_init(tdtcp_reno_register);
module_exit(tdtcp_reno_unregister);

MODULE_AUTHOR("Shawn Chen <shuoshuc@cs.cmu.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TDTCP Reno");
