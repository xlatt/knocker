#include <linux/module.h>	// Needed by all modules
#include <linux/kernel.h>	// Needed for KERN_INFO
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

static struct nf_hook_ops hook_check_port;
static struct nf_hook_ops hook_insert_rst;

static time_t port_knocks[3];

static bool port_hidden;

static DECLARE_RWSEM(port_hidden_lock);
static DECLARE_RWSEM(knock_lock);

static void insert_port_knock(__be16 port)
{
	time_t now;
	struct timespec tm;

	printk(KERN_INFO "[KNOCKER] inserting port knock for port: %d", port);

	getnstimeofday(&tm);
	now = tm.tv_sec;

	switch (port) {
	case KPORT_1:
		locked_assignment(knock_lock, port_knocks[0], now);
		break;
	case KPORT_2:
		locked_assignment(knock_lock, port_knocks[1], now);
		break;
	case KPORT_3:
		locked_assignment(knock_lock, port_knocks[2], now);
		break;
	default:
		printk(KERN_ERR "[KNOCKER] invalid knock port: %d", port);
	}	
}


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
		printk(KERN_INFO "[KNOCKER] knock NOT OK");
		return false;
	}
	
	printk(KERN_INFO "[KNOCKER] knock OK");
	return true;
}


static bool is_port_hidden(void)
{
	bool ret = false;
	printk(KERN_INFO "[KNOCKER] checking if port is hidden");
	
	down_read(&port_hidden_lock);
	ret = port_hidden;
	up_read(&port_hidden_lock);

	return ret;
}


static void do_hide_port(void)
{
	printk(KERN_INFO "[KNOCKER] hiding port");

	locked_assignment(port_hidden_lock, port_hidden, true);
}


static void do_unhide_port(void)
{
	printk(KERN_INFO "[KNOCKER] un-hiding port");
	
	locked_assignment(port_hidden_lock, port_hidden, false);
}


static unsigned int check_dst_port(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *th;
	struct iphdr *ih;
 	__be16 dport = 0;

	printk(KERN_INFO "[KNOCKER] hook func called\n");

	th = (struct tcphdr*)skb_transport_header(skb);
	ih = (struct iphdr*)skb_network_header(skb);

	if (ih->protocol == IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	
	dport = ntohs(th->dest);

	if (dport == HIDE_PORT && !is_port_hidden() && !knock_ok()) {
		do_hide_port();
		return NF_ACCEPT;
	}
	
	switch (dport) {
	case KPORT_1:
		insert_port_knock(KPORT_1);
		break;
	case KPORT_2:
		insert_port_knock(KPORT_2);
		break;
	case KPORT_3:
		insert_port_knock(KPORT_3);
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
		printk(KERN_INFO "[KNOCKER] changing flag to RST");
		th->rst = 1;
		th->ack = 0;
	}

	return NF_ACCEPT;
}


int init_module(void)
{
	printk(KERN_INFO "[KNOCKER] module loaded\n");

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
	printk(KERN_INFO "[KNOCKER] module unloaded\n");

	nf_unregister_hook(&hook_check_port);
	nf_unregister_hook(&hook_insert_rst);
}

MODULE_LICENSE("GPL v2");
