# Setup

## Requirements

## Using the orivded Vrirtual Machine

# Basic program

## Hello, world

Let's start simple with a "hello world" program. This will be the occasion to
get familiar with the process of compiling and loading a program, as well as
reading log messages from running eBPF programs.

go in the `src` folder, and let's start our journey by creating our program.

A common practise is to name eBPF programs `<name>.bpf.c`, so name the program
`dns-filter.bpf.c`.

Open it in your favorite text editor, and add the basic skeleton :

```
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

SEC("tc")
int dns_filter(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
```

The `SEC` macro defines the ELF section in which the program is going to be
stored in the final object file, we need it to be stored in the "tc" section.

The `dns_filter` function is our program's entry point. This function will be
executed every time we send a packet ! It takes as a parameter a `struct __sk_buff`
object, that represents the content of our packet. The definition of the struct
can be found here (link).

If the function returns `TC_ACT_OK`, it means that we allow the packet to be sent.
To drop a packet, we simply need to return `TC_ACT_SHOT` instead. There are more
actions that can be returned, you can see the full list here (link).

For now, we just want to make sure that we are able to compile and load an eBPF
program and attach it to the TC hook. We however want know that our program is
working, and what better option than to print a nice "hello, world!" !

The main logging function in eBPF is `bpf_trace_printk`, but it's a bit cumbersome
to use as we have to declare the format string on the stack ahead of time :

```
const char fmt[] = "Hello, world\n";

bpf_trace_printk(fmt, sizeof(fmt));
```

A wrapper macro named `bpf_printk` is provided by libbpf, which makes it more
convenient to use. Insert the following line above the `return` statement:

```
    bpf_printk("Hello, world !\n");
```

To compile our program, we'll use Clang from the LLVM tools :

```
clang -g -O2 -target bpf -c dns_filter.bpf.c -o dns_filter.bpf.o
```

Congratulations, you have produced your first eBPF binary !

## Hello, traffic control

To load our first program, we'll use the tc command to create a new filter,
and attach our program to it.

```
tc qdisc add dev <interface> handle 1: root cake
tc filter add dev <interface> parent 1: bpf obj dns_filter.bpf.o sec tc
```

Let's check the trace for our logs :

```
bpftool prog tracelog
```

You should now see all your hello world when your machine sends traffic to the
outside world ! What we will want to do next is identify, among all these packets,
the ones that correspond to DNS requests towards unwanted domains, and drop them.

TODO : tc cleanup

# Identify IP frames

The first step in our journey to identify DNS requests will be to first identify
ethernet frames that contain IP packets. The `skb` that is passed to our program
contains a field named `data`, that is a pointer to the beginning of the data we
want to send over the network. Even if we may want to send this frame over a
wireless network, our frame starts with an Ethernet Header :

To fetch data from our `skb`, we'll use the bpf helper `bpf_skb_load_bytes` :

```
long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len)
```

This function returns 0 on success.

It's common when accessing data from the header of a packet to load it into a
C struct that maps each field directly. For example, there exists a `struct ethhdr`
provided by `<linux/if_ether.h>` that directly maps an ethernet header :

```
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
}

```

In your eBPF program, declare an object of type `struct ethhdr`, and fill it
with the content of the Ethernet header :

```
struct ethhdr ethhdr;
int ret;

ret = bpf_skb_load_bytes(skb, 0, &ethhdr, sizeof(ethhdr));
if (ret)
    return TC_ACT_OK;
```

It is _very_ important to check the return codes from the BPF helpers. If you
don't, the verifier may refuse to load the program altogether.

Now that we have the Ethernet header accessible, we need to check if it contains
either an IPv4 header, or an IPv6 header. This information is accessible in the
`h_proto` field of the ethernet header, however it is stored in "Network Endianness".

This is a Big Endian representation of the data, which needs to be converted
back to the "Native Endianness" of our CPU. This is done by using the helper
`__bpf_constant_htons` :

```
if (ethhdr.h_proto == __bpf_constant_htons(ETH_P_IP) {
    ...
}
```

The values in the `h_proto` field are called "Ethertyp", and are defined as part
of ieee standard :

https://standards-oui.ieee.org/ethertype/eth.txt

There are macros provided by the C library that wraps these, that you can find
here (link). For example, IPv4 packets are mapped to the `ETH_P_IP` macro.

Update your program to pass any packet that isn't IPv4 or IPv6, as we are only
going to consider these types.

# Identify UDP packets

At that point, we either have an IPv4 packet, or an IPv6 one. Both of these
can encapsulate UDP, which we're interested in as this is what conveys DNS
requests.

IPv4 and IPv6 are represented respectively by `struct iphdr` and `struct ip6hdr`.

In a similar fashion to the previous step, IPv4 headers have information about
wether they encapsulate TCP, UDP or something else in the "proto" field. For IPv6,
this is stored in the "next header" field :

_image todo_

To map the IPv4 or IPv6 headers, you need to skip the Ethernet header while
loading the IP header :

```
# IPv4 header mapping
ret = bpf_skb_load_bytes(skb, ETH_HLEN,  &iph, sizeof(iph));
if (ret)
    return TC_ACT_OK;
```


# Identify DNS datagrams

DNS acts on port 53. Extract that field from the header, and let any traffic that
doesn't have that destination port pass.

Keep in mind that the port field is a 2 byte value in network endianness !

_image _


# Identify DNS requests

A DNS query has the following header :

```
struct dnshdr {
        __be16 trans_id;
        __be16 flags;
        __be16 nr_quest;
        __be16 nr_answ;
        __be16 nr_auth_rr;
        __be16 add_rr;
};
```

# Extract the DNS query

The dns query has the following format :

([size][domain]) n times

aaaaaaaaaa

# Introducing a denylist

# Create a dedicated tool

# Going further
