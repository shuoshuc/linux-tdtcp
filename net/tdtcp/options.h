/* SPDX-License-Identifier: GPL-2.0 */
/* TDTCP protocol definitions and common data strcutures.
 *
 * Shawn Chen <shuoshuc@cs.cmu.edu>
 * Carnegie Mellon University 2020.
 */

#ifndef __TDTCP_OPTIONS_H
#define __TDTCP_OPTIONS_H

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

#endif /* __TDTCP_OPTIONS_H */
