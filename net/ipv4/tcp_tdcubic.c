// SPDX-License-Identifier: GPL-2.0-only
/*
 * A TCP CUBIC implementation customized for TDTCP.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>
#include <net/tdtcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta_us __read_mostly = 2000;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (usec) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
} td_bic[MAX_NUM_TDNS];

static inline void bictcp_reset(struct bictcp *td_bic, u8 tdn)
{
	td_bic[tdn].cnt = 0;
	td_bic[tdn].last_max_cwnd = 0;
	td_bic[tdn].last_cwnd = 0;
	td_bic[tdn].last_time = 0;
	td_bic[tdn].bic_origin_point = 0;
	td_bic[tdn].bic_K = 0;
	td_bic[tdn].delay_min = 0;
	td_bic[tdn].epoch_start = 0;
	td_bic[tdn].ack_cnt = 0;
	td_bic[tdn].tcp_cwnd = 0;
	td_bic[tdn].found = 0;
}

static inline u32 bictcp_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

static inline void bictcp_hystart_reset(struct sock *sk, u8 tdn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *td_bic = inet_csk_ca(sk);

	td_bic[tdn].round_start = td_bic[tdn].last_ack = bictcp_clock_us(sk);
	td_bic[tdn].end_seq = tp->snd_nxt;
	td_bic[tdn].curr_rtt = ~0U;
	td_bic[tdn].sample_cnt = 0;
}

static void tdtcp_cubic_init(struct sock *sk)
{
	struct bictcp *td_bic = inet_csk_ca(sk);
	int i;

	for (i = 0; i < MAX_NUM_TDNS; i++) {
		bictcp_reset(td_bic, i);
	}

	if (hystart) {
		for (i = 0; i < MAX_NUM_TDNS; i++) {
			bictcp_hystart_reset(sk, i);
		}
	}

	if (!hystart && initial_ssthresh) {
		for (i = 0; i < MAX_NUM_TDNS; i++) {
			td_set_ssthresh(tcp_sk(sk), i, initial_ssthresh);
		}
	}
}

static void tdtcp_cubic_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *td_bic = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;
		u8 curr_tdn = GET_TDN(tcp_sk(sk));

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (td_bic[curr_tdn].epoch_start && delta > 0) {
			td_bic[curr_tdn].epoch_start += delta;
			if (after(td_bic[curr_tdn].epoch_start, now))
				td_bic[curr_tdn].epoch_start = now;
		}
		return;
	}
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *td_bic, u32 cwnd, u32 acked, u8 tdn)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	td_bic[tdn].ack_cnt += acked;	/* count the number of ACKed packets */

	if (td_bic[tdn].last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - td_bic[tdn].last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update td_bic[tdn].cnt at most once per jiffy.
	 * On all cwnd reduction events, td_bic[tdn].epoch_start is set to 0,
	 * which will force a recalculation of td_bic[tdn].cnt.
	 */
	if (td_bic[tdn].epoch_start && tcp_jiffies32 == td_bic[tdn].last_time)
		goto tcp_friendliness;

	td_bic[tdn].last_cwnd = cwnd;
	td_bic[tdn].last_time = tcp_jiffies32;

	if (td_bic[tdn].epoch_start == 0) {
		td_bic[tdn].epoch_start = tcp_jiffies32;	/* record beginning */
		td_bic[tdn].ack_cnt = acked;			/* start counting */
		td_bic[tdn].tcp_cwnd = cwnd;			/* syn with cubic */

		if (td_bic[tdn].last_max_cwnd <= cwnd) {
			td_bic[tdn].bic_K = 0;
			td_bic[tdn].bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			td_bic[tdn].bic_K = cubic_root(cube_factor
					       * (td_bic[tdn].last_max_cwnd - cwnd));
			td_bic[tdn].bic_origin_point = td_bic[tdn].last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - td_bic[tdn].epoch_start);
	t += usecs_to_jiffies(td_bic[tdn].delay_min);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < td_bic[tdn].bic_K)		/* t - K */
		offs = td_bic[tdn].bic_K - t;
	else
		offs = t - td_bic[tdn].bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < td_bic[tdn].bic_K)                            /* below origin*/
		bic_target = td_bic[tdn].bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = td_bic[tdn].bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		td_bic[tdn].cnt = cwnd / (bic_target - cwnd);
	} else {
		td_bic[tdn].cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (td_bic[tdn].last_max_cwnd == 0 && td_bic[tdn].cnt > 20)
		td_bic[tdn].cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;
		while (td_bic[tdn].ack_cnt > delta) {		/* update tcp cwnd */
			td_bic[tdn].ack_cnt -= delta;
			td_bic[tdn].tcp_cwnd++;
		}

		if (td_bic[tdn].tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = td_bic[tdn].tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (td_bic[tdn].cnt > max_cnt)
				td_bic[tdn].cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	td_bic[tdn].cnt = max(td_bic[tdn].cnt, 2U);
}

static void tdtcp_cubic_cong_avoid(struct sock *sk, u32 ack, u32 acked, u8 tdn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *td_bic = inet_csk_ca(sk);

	if (!tdtcp_is_cwnd_limited(sk, tdn))
		return;

	if (tcp_in_slow_start(tp, tdn)) {
		if (hystart && after(ack, td_bic[tdn].end_seq))
			bictcp_hystart_reset(sk, tdn);
		acked = tdtcp_slow_start(tp, acked, tdn);
		if (!acked)
			return;
	}
	bictcp_update(td_bic, td_get_cwnd(tp, tdn), acked, tdn);
	tdtcp_cong_avoid_ai(tp, td_bic[tdn].cnt, acked, tdn);
}

static u32 tdtcp_cubic_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *td_bic = inet_csk_ca(sk);
	u8 curr_tdn = GET_TDN(tp);

	td_bic[curr_tdn].epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (td_get_cwnd(tp, curr_tdn) < td_bic[curr_tdn].last_max_cwnd &&
	    fast_convergence)
		td_bic[curr_tdn].last_max_cwnd = (td_get_cwnd(tp, curr_tdn) *
						  (BICTCP_BETA_SCALE + beta))
						  / (2 * BICTCP_BETA_SCALE);
	else
		td_bic[curr_tdn].last_max_cwnd = td_get_cwnd(tp, curr_tdn);

	return max((td_get_cwnd(tp, curr_tdn) * beta) / BICTCP_BETA_SCALE, 2U);
}

static void tdtcp_cubic_state(struct sock *sk, u8 new_state)
{
	u8 tdn = GET_TDN(tcp_sk(sk));
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk), tdn);
		bictcp_hystart_reset(sk, tdn);
	}
}

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static u32 hystart_ack_delay(struct sock *sk, u8 tdn)
{
	unsigned long rate;

	rate = td_get_pacing_rate(sk, tdn);
	if (!rate)
		return 0;
	return min_t(u64, USEC_PER_MSEC,
		     div64_ul((u64)GSO_MAX_SIZE * 4 * USEC_PER_SEC, rate));
}

static void hystart_update(struct sock *sk, u32 delay, u8 tdn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *td_bic = inet_csk_ca(sk);
	u32 threshold;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = bictcp_clock_us(sk);

		/* first detection parameter - ack-train detection */
		if ((s32)(now - td_bic[tdn].last_ack) <= hystart_ack_delta_us) {
			td_bic[tdn].last_ack = now;

			threshold = td_bic[tdn].delay_min + hystart_ack_delay(sk, tdn);

			/* Hystart ack train triggers if we get ack past
			 * td_bic[tdn].delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start.
			 */
			if (sk->sk_pacing_status == SK_PACING_NONE)
				threshold >>= 1;

			if ((s32)(now - td_bic[tdn].round_start) > threshold) {
				td_bic[tdn].found = 1;
				pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
					 now - td_bic[tdn].round_start, threshold,
					 td_bic[tdn].delay_min, hystart_ack_delay(sk, tdn),
					 td_get_cwnd(tp, tdn));
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      td_get_cwnd(tp, tdn));
				td_set_ssthresh(tp, tdn, td_get_cwnd(tp, tdn));
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (td_bic[tdn].curr_rtt > delay)
			td_bic[tdn].curr_rtt = delay;
		if (td_bic[tdn].sample_cnt < HYSTART_MIN_SAMPLES) {
			td_bic[tdn].sample_cnt++;
		} else {
			if (td_bic[tdn].curr_rtt > td_bic[tdn].delay_min +
			    HYSTART_DELAY_THRESH(td_bic[tdn].delay_min >> 3)) {
				td_bic[tdn].found = 1;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      td_get_cwnd(tp, tdn));
				td_set_ssthresh(tp, tdn, td_get_cwnd(tp, tdn));
			}
		}
	}
}

static void tdtcp_cubic_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *td_bic = inet_csk_ca(sk);
	u32 delay;
	u8 curr_tdn = GET_TDN(tp);

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (td_bic[curr_tdn].epoch_start &&
	    (s32)(tcp_jiffies32 - td_bic[curr_tdn].epoch_start) < HZ)
		return;

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (td_bic[curr_tdn].delay_min == 0 ||
	    td_bic[curr_tdn].delay_min > delay)
		td_bic[curr_tdn].delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (!td_bic[curr_tdn].found && tcp_in_slow_start(tp, curr_tdn) && hystart &&
	    td_get_cwnd(tp, curr_tdn) >= hystart_low_window)
		hystart_update(sk, delay, curr_tdn);
}

/* This is the same as tdtcp_reno_undo_cwnd(). */
static u32 tdtcp_cubic_undo_cwnd(struct sock *sk, const u8 tdn)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(td_get_cwnd(tp, tdn), td_get_prior_cwnd(tp, tdn));
}

static struct tcp_congestion_ops tdtcp_cubic __read_mostly = {
	.init		= tdtcp_cubic_init,
	.ssthresh	= tdtcp_cubic_recalc_ssthresh,
	.cong_avoid	= tdtcp_cubic_cong_avoid,
	.set_state	= tdtcp_cubic_state,
	.undo_cwnd	= tdtcp_cubic_undo_cwnd,
	.cwnd_event	= tdtcp_cubic_cwnd_event,
	.pkts_acked     = tdtcp_cubic_acked,
	.owner		= THIS_MODULE,
	.name		= "tdcubic",
};

static int __init tdtcp_cubic_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) * MAX_NUM_TDNS > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8 * (BICTCP_BETA_SCALE + beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	return tcp_register_congestion_control(&tdtcp_cubic);
}

static void __exit tdtcp_cubic_unregister(void)
{
	tcp_unregister_congestion_control(&tdtcp_cubic);
}

module_init(tdtcp_cubic_register);
module_exit(tdtcp_cubic_unregister);

MODULE_AUTHOR("Shawn Chen <shuoshuc@cs.cmu.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TDTCP CUBIC");