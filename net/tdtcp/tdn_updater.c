// SPDX-License-Identifier: GPL-2.0-or-later
/* TDN updater work queue defined to support ICMP TDN change updates. It does
 * not need to be flag protected by CONFIG_TDTCP since the work queue itself
 * does not depend on anything TDTCP specific. It just will not be used when
 * TDTCP is disabled.
 */
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <net/tdtcp.h>

MODULE_LICENSE("GPL");

struct workqueue_struct *tdn_updater_wq;
EXPORT_SYMBOL(tdn_updater_wq);

void tdn_update_handler(struct work_struct *work)
{
	struct tdn_work_data *data = container_of(work, struct tdn_work_data,
						  tdn_work);

	pr_info("[tdn_updater_wq] %s: sk=%p, tdn=%u. Acquiring lock.\n",
		__FUNCTION__, data->sk, data->tdn_id);
	lock_sock(data->sk);
	pr_info("[tdn_updater_wq] %s: Lock acquired.\n", __FUNCTION__);
	WRITE_ONCE(tcp_sk(data->sk)->curr_tdn_id, data->tdn_id);
	release_sock(data->sk);
	pr_info("[tdn_updater_wq] %s: Lock released.\n", __FUNCTION__);

	kfree(data);
}
EXPORT_SYMBOL(tdn_update_handler);

static int tdn_updater_wq_init(void)
{
	pr_info("tdn_updater_wq: %s create wq.\n", __FUNCTION__);
	tdn_updater_wq = create_workqueue("tdn_updater");
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
