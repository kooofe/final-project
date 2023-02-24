#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Define the sequence of bytes to monitor
static const char* SEQUENCE = "example";

// Declare the netfilter hook function
static unsigned int hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
    // Check if the packet is an IPv4 packet
    if (skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    // Get a pointer to the IP header
    struct iphdr* iph = ip_hdr(skb);

    // Check if the packet is a TCP packet
    if (iph->protocol == IPPROTO_TCP) {
        // Get a pointer to the TCP header
        struct tcphdr* tcph = tcp_hdr(skb);

        // Get a pointer to the payload
        char* payload = (char*)(tcph + 1);

        // Get the length of the payload
        int payload_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);

        // Search for the sequence of bytes
        char* found = strstr(payload, SEQUENCE);
        if (found != NULL) {
            // The sequence of bytes was found, so drop the packet
            printk(KERN_INFO "Dropping packet containing sequence: %s\n", SEQUENCE);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// Declare the netfilter hook struct
static struct nf_hook_ops nfho = {
    .hook = hook_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// Initialize the module
static int __init init_module(void)
{
    printk(KERN_INFO "Initializing netfilter module\n");

    // Register the netfilter hook
    nf_register_hook(&nfho);

    return 0;
}

// Cleanup the module
static void __exit cleanup_module(void)
{
    printk(KERN_INFO "Cleaning up netfilter module\n");

    // Unregister the netfilter hook
    nf_unregister_hook(&nfho);
}

// Module declarations
module_init(init_module);
module_exit(cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adema Bauyrzhankyzy, Arlan Manap, Dilnaz Sadyrbayeva");
MODULE_DESCRIPTION("A simple example of netfilter kernel module that monitors IPv4 traffic for a specific sequence of bytes.");
