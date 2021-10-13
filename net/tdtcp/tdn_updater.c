// SPDX-License-Identifier: GPL-2.0-or-later
/* TDN updater work queue defined to support ICMP TDN change updates. It does
 * not need to be flag protected by CONFIG_TDTCP since the work queue itself
 * does not depend on anything TDTCP specific. It just will not be used when
 * TDTCP is disabled.
 */
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <net/tdtcp.h>

MODULE_LICENSE("GPL");

struct workqueue_struct *tdn_updater_wq;
EXPORT_SYMBOL(tdn_updater_wq);

u8 global_tdn_id;
EXPORT_SYMBOL(global_tdn_id);

void tdn_update_handler(struct work_struct *work)
{
	struct tdn_work_data *data = container_of(work, struct tdn_work_data,
						  tdn_work);
	WARN_ON(!data);
	WARN_ON(!data->sk);
	struct tcp_sock *tp = tcp_sk(data->sk);
	/* cache the old TDN before updating. */
	u8 prev_tdn = GET_TDN(tp);
	/* No need to set same TDN again. This saves locking overhead. */
	if (data->tdn_id == prev_tdn)
		goto free;

	lock_sock(data->sk);
	/* update curr_tdn in sk */
	SET_TDN(tp, data->tdn_id);
	/* initialize bound_low and bound_high for the current TDN. */
	td_set_bound_low(tp, data->tdn_id, tp->snd_nxt);
	td_set_bound_high(tp, data->tdn_id, tp->snd_nxt);
	/* finalize bound_high for the previous TDN. */
	td_set_bound_high(tp, prev_tdn, tp->snd_nxt);
	release_sock(data->sk);
	pr_debug("[%s] %llu ns since epoch. sk=%p, tdn=%u.\n",
		 __FUNCTION__, ktime_get_real_fast_ns(), data->sk, data->tdn_id);

free:
	kfree(data);
}
EXPORT_SYMBOL(tdn_update_handler);

static int tdn_updater_wq_init(void)
{
	pr_info("tdn_updater_wq: %s create wq.\n", __FUNCTION__);
	tdn_updater_wq = alloc_ordered_workqueue("tdn_updater", WQ_MEM_RECLAIM);
	BUG_ON(!tdn_updater_wq);

	return 0;
}

static void tdn_updater_wq_exit(void)
{
	pr_info("tdn_updater_wq: %s flush wq.\n", __FUNCTION__);
	flush_workqueue(tdn_updater_wq);
	pr_info("tdn_updater_wq: %s destroy wq.\n", __FUNCTION__);
	destroy_workqueue(tdn_updater_wq);
}

module_init(tdn_updater_wq_init);
module_exit(tdn_updater_wq_exit);
