// Adapted from https://elixir.bootlin.com/linux/v6.5.7/source/tools/testing/selftests/bpf/progs/dev_cgroup.c

/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/dev")
int bpf_prog1(struct bpf_cgroup_dev_ctx *ctx)
{
	short type = ctx->access_type & 0xFFFF;
#ifdef DEBUG
	short access = ctx->access_type >> 16;
	char fmt[] = "  %d:%d    \n";

	switch (type) {
	case BPF_DEVCG_DEV_BLOCK:
		fmt[0] = 'b';
		break;
	case BPF_DEVCG_DEV_CHAR:
		fmt[0] = 'c';
		break;
	default:
		fmt[0] = '?';
		break;
	}

	if (access & BPF_DEVCG_ACC_READ)
		fmt[8] = 'r';

	if (access & BPF_DEVCG_ACC_WRITE)
		fmt[9] = 'w';

	if (access & BPF_DEVCG_ACC_MKNOD)
		fmt[10] = 'm';

	bpf_trace_printk(fmt, sizeof(fmt), ctx->major, ctx->minor);
#endif

	/* Deny access to /dev/zero and /dev/random.
	 * Allow everything else.
	 */
	if (ctx->major != 195 || type != BPF_DEVCG_DEV_CHAR)
		return 1;

        // TODO: see how to use a map and interact directly with userland to 
        // control which devices get allowed and denied
	switch (ctx->minor) {
	case 0: /* 195:0 /dev/nvidia0 */
		return 0;
	}

	return 1;
}
char _license[] SEC("license") = "GPL";
