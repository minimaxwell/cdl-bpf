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

The main logging function in eBPF is `bpf_printk`, which is a wrapper around
the `bpf_trace_printk` function. Insert this line in the program, above the
`return` statement :

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

# Identify IP frames

Lookup the ethertype in the ethernet header.

Wew need to handle both ipv4 and ipv6. Lookup the ethertype, and load the correct
ip packet.

# Identify UDP packets

The proto field (or next-header for ipv6) indicate if the Transport layer protocol
is TCP, UDP or something else. Get that, and load the UDP header if applicable

# Identify DNS datagrams

DNS acts on port 53. Extract that field from the header, and let any traffic that
doesn't have that destination port pass.

Keep in mind that the port field is a 2 byte value in network endianness !



# Identify DNS requests

We have provided a struct that maps the DNS header.

# Extract the DNS query

The dns query has the following format :

([size][domain]) n times

# Introducing a denylist

# Create a dedicated tool

# Going further
