#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rwsem.h>
#include <linux/time.h>

#define KPORT_1 14234
#define KPORT_2 9786
#define KPORT_3  32232
#define HIDE_PORT  111

#define locked_assignment(lock, x, y)		\
	down_write(&lock); 			\
	x = y;					\
	up_write(&lock);

#define DBG_PRINT

#ifdef DBG_PRINT
	#define print_dbg(msg) printk(KERN_DEBUG msg)
#else
	#define print_dbg(msg)
#endif

static struct nf_hook_ops hook_check_port;
static struct nf_hook_ops hook_insert_rst;

static time_t port_knocks[3];

static bool port_hidden;

static DECLARE_RWSEM(port_hidden_lock);
static DECLARE_RWSEM(knock_lock);


static bool knock_ok(void)
{	
	int d0 = 0;
	int d1 = 0;
	time_t now;
	time_t last_knock;
	time_t delta;
	struct timespec tm;

	down_read(&knock_lock);
	d0 = port_knocks[1] - port_knocks[0];
	d1 = port_knocks[2] - port_knocks[1];
	last_knock = port_knocks[2];
	up_read(&knock_lock);

	getnstimeofday(&tm);
	now = tm.tv_sec;

	delta = now - last_knock;

	if (delta > 5 || (d0 > 3 || d1 > 3)) {
		print_dbg("[KNOCKER] knock NOT OK");
		return false;
	}
	
	print_dbg("[KNOCKER] knock OK");
	return true;
}


static bool is_port_hidden(void)
{
	bool ret = false;
	print_dbg("[KNOCKER] checking if port is hidden");
	
	down_read(&port_hidden_lock);
	ret = port_hidden;
	up_read(&port_hidden_lock);

	return ret;
}


static void do_hide_port(void)
{
	print_dbg("[KNOCKER] hiding port");

	locked_assignment(port_hidden_lock, port_hidden, true);
}


static void do_unhide_port(void)
{
	print_dbg("[KNOCKER] un-hiding port");
	
	locked_assignment(port_hidden_lock, port_hidden, false);
}


static time_t get_time(void)
{
	struct timespec tm;

	getnstimeofday(&tm);
	return tm.tv_sec;
	
}

static unsigned int check_dst_port(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *th;
	struct iphdr *ih;
 	__be16 dport = 0;
	time_t now = 0;

	print_dbg("[KNOCKER] hook func called");

	ih = (struct iphdr*)skb_network_header(skb);

	if (ih->protocol == IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	
	th = (struct tcphdr*)skb_transport_header(skb);
	dport = ntohs(th->dest);

	if (dport == HIDE_PORT && !is_port_hidden() && !knock_ok()) {
		do_hide_port();
		return NF_ACCEPT;
	}

	now = get_time();
	
	switch (dport) {
	case KPORT_1:
		locked_assignment(knock_lock, port_knocks[0], now);
		break;
	case KPORT_2:
		locked_assignment(knock_lock, port_knocks[1], now);
		break;
	case KPORT_3:
		locked_assignment(knock_lock, port_knocks[2], now);
		if (knock_ok() && is_port_hidden())
			do_unhide_port();
		break;
	}

	return NF_ACCEPT;
}


static unsigned int insert_rst(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *th;
	struct iphdr *ih;
	__be16 sport = 0;

	th = (struct tcphdr*)skb_transport_header(skb);
	ih = (struct iphdr*)skb_network_header(skb);

	if (ih->protocol == IPPROTO_UDP)
		return NF_ACCEPT;

	sport = ntohs(th->source);

	if (sport == HIDE_PORT && is_port_hidden()) {
		print_dbg("[KNOCKER] changing flag to RST");
		th->rst = 1;
		th->ack = 0;
	}

	return NF_ACCEPT;
}


int init_module(void)
{
	print_dbg("[KNOCKER] module loaded\n");

	port_hidden = false;
	port_knocks[0] = 0;
	port_knocks[1] = 10;
	port_knocks[2] = 20;


	hook_check_port.hook = check_dst_port;
	hook_check_port.hooknum = NF_INET_PRE_ROUTING;
	hook_check_port.pf = PF_INET;
	hook_check_port.priority = NF_IP_PRI_FIRST;

	hook_insert_rst.hook = insert_rst;
	hook_insert_rst.hooknum = NF_INET_POST_ROUTING;
	hook_insert_rst.pf = PF_INET;
	hook_insert_rst.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&hook_check_port);
	nf_register_hook(&hook_insert_rst);

	return 0;
}


void cleanup_module(void)
{
	print_dbg("[KNOCKER] module unloaded\n");

	nf_unregister_hook(&hook_check_port);
	nf_unregister_hook(&hook_insert_rst);
}

MODULE_LICENSE("GPL v2");
