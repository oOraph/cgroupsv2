/* Copyright (c) 2023 Hugging Face
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#define DEBUG

// Ugh -> for loops not well supported in bpf even when bounded. Should work when bounded, dunno why.
// Ugly workaround
// v = (struct myval *) bpf_map_lookup_elem(&raph_map, &i);
#define MYITER(idx) \
    i = idx; \
    v = (unsigned long long *) bpf_map_lookup_elem(&raph_map, &i); \
    if (v == NULL || *v == 0) { \
        bpf_trace_printk("no map\n", sizeof("no map\n")); \
        bpf_trace_printk(permitted, sizeof(permitted)); \
        return 1; \
    } \
    minor = (unsigned int) *v; \
    major = (unsigned int) (*v >> 32); \
    bpf_trace_printk(debug1, sizeof(debug1), major, minor); \
    if(ctx->major == major && ctx->minor == minor) { \
        bpf_trace_printk(denied, sizeof(denied)); \
        return 0; \
    }

// struct myval {
//     unsigned int major;
//     unsigned int minor;
// };

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, unsigned long long);
        __uint(max_entries, 10);
} raph_map SEC(".maps");

SEC("cgroup/dev")
int bpf_prog2(struct bpf_cgroup_dev_ctx *ctx)
{
	short type = ctx->access_type & 0xFFFF;
#ifdef DEBUG
	short access = ctx->access_type >> 16;
	char fmt[] = "  %d:%d    \n";
    char debug1[] = "%d:%d found in map\n";
    char denied[] = "device access denied\n";
    char permitted[] = "device access permitted\n";

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

	//if (ctx->major != 195 || type != BPF_DEVCG_DEV_CHAR)
    // Shortcut we only want to consider nvidia devices (TODO, add major after debugged)
	if (type != BPF_DEVCG_DEV_CHAR)
        // No printk in such case
    	return 1;

    int i = 0;
    unsigned long long *v;
    unsigned int major, minor;

    MYITER(0)
    MYITER(1)
    MYITER(2)
    MYITER(3)
    MYITER(4)

#ifdef DEBUG
    bpf_trace_printk(permitted, sizeof(permitted));
#endif
	return 1;
}
char _license[] SEC("license") = "GPL";
