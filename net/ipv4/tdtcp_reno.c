// SPDX-License-Identifier: GPL-2.0-only
/*
 * A TCP Reno implementation customized for TDTCP.
 */

#include <net/tcp.h>

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
