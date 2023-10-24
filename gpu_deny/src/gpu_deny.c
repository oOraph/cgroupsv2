/* Copyright (c) 2023 Hugging Face
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// BPF common program

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

// Ugh -> for loops not well supported in bpf even when bounded. Should work when bounded, dunno why.
// Ugly workaround
// v = (struct myval *) bpf_map_lookup_elem(&raph_map, &i);
#define MYITERDBG(idx) \
    i = idx; \
    v = (unsigned long long *) bpf_map_lookup_elem(&gpu_deny_map, &i); \
    if (v == 0 || *v == 0) { \
        bpf_trace_printk(nomap, sizeof(nomap), i); \
        bpf_trace_printk(denied, sizeof(denied)); \
        return 0; \
    } \
    minor = (unsigned int) *v; \
    major = (unsigned int) (*v >> 32); \
    bpf_trace_printk(debug1, sizeof(debug1), major, minor); \
    if(ctx->major == major && ctx->minor == minor) { \
        bpf_trace_printk(permitted, sizeof(permitted)); \
        return 1; \
    }

#define MYITER(idx) \
    i = idx; \
    v = (unsigned long long *) bpf_map_lookup_elem(&gpu_deny_map, &i); \
    if (v == 0 || *v == 0) { \
        return 0; \
    } \
    minor = (unsigned int) *v; \
    major = (unsigned int) (*v >> 32); \
    if(ctx->major == major && ctx->minor == minor) { \
        return 1; \
    }

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, unsigned long long);
        __uint(max_entries, 10);
} gpu_deny_map SEC(".maps");

SEC("cgroup/dev")
int gpu_deny(struct bpf_cgroup_dev_ctx *ctx)
{
	short type = ctx->access_type & 0xFFFF;
    short access = ctx->access_type >> 16;

#ifdef DEBUG
    char fmt[] = "  %d:%d    \n";
    char debug1[] = "%d:%d found in map\n";
    char denied[] = "device access denied\n";
    char permitted[] = "device access permitted\n";
    char nomap[] = "no map or no entry index %d in map\n";
    char noway[] = "no way you mknod anything !\n";

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

    if(access & BPF_DEVCG_ACC_MKNOD) {
#ifdef DEBUG
        bpf_trace_printk(noway, sizeof(noway));
        bpf_trace_printk(denied, sizeof(denied));
#endif
        return 0;
    }

    // Shortcut we only want to consider nvidia devices except (/dev/nvidiactl, /dev/nvidia-modeset)
	if (ctx->major != 195 || type != BPF_DEVCG_DEV_CHAR ||
        (ctx->major == 195 && (ctx->minor == 255 || ctx->minor == 254))) {
#ifdef DEBUG
        bpf_trace_printk(permitted, sizeof(permitted));
#endif
    	return 1;
    }

    int i = 0;
    unsigned long long *v;
    unsigned int major, minor;

#ifdef DEBUG
    MYITERDBG(0)
    MYITERDBG(1)
    MYITERDBG(2)
    MYITERDBG(3)
    MYITERDBG(4)
    MYITERDBG(5)
    MYITERDBG(6)
    MYITERDBG(7)
    MYITERDBG(8)
    MYITERDBG(9)
    bpf_trace_printk(denied, sizeof(denied));
#else
    // We can add up to 10 devices
    MYITER(0)
    MYITER(1)
    MYITER(2)
    MYITER(3)
    MYITER(4)
    MYITER(5)
    MYITER(6)
    MYITER(7)
    MYITER(8)
    MYITER(9)
#endif
	return 0;
}
char _license[] SEC("license") = "GPL";
