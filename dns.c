#include "dns_check.skel.h"
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>

/* cleanup : sudo tc qdisc delete dev wlp0s20f3 parent ffff:fff */

int main(int argc, char **argv)
{
	int fd, ifindex, ret;
	struct dns_bpf *dns;
	int key;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .priority = 1);

	if (argc < 2)
		return -1;

	dns = dns_bpf__open_and_load();
	if (!dns)
		return -1;

	fd = bpf_program__fd(dns->progs.dns_catcher);

	ifindex = if_nametoindex(argv[1]);

	hook.ifindex = ifindex;
	opts.prog_fd = fd;

	/* TODO : Signal handler for cleanup */
	ret = bpf_tc_hook_create(&hook);
	if (ret)
		return ret;

	ret = bpf_tc_attach(&hook, &opts);
	if (ret) {
		bpf_tc_hook_destroy(&hook);
		return ret;
	}

	key = 0;
	const char val[128] = "docs.ebpf.io";

	ret = bpf_map_update_elem(bpf_map__fd(dns->maps.array), &key, &val, BPF_ANY);
	if (ret) {
		printf("Can't insert elem in map\n");
		return -1; /* TODO cleanup */
	}

	/* Create QDisc */
	while (1) {
		sleep(1);
	}

	bpf_tc_detach(&hook, &opts);
	bpf_tc_hook_destroy(&hook);
	dns_bpf__destroy(dns);

	return 0;
}
