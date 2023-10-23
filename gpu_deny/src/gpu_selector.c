// Userland PoC prgm
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    char pathname[] = "/sys/fs/bpf/gpu_deny_map";
    printf("Loading map in userland\n");
    int fd = bpf_obj_get(pathname);
    if (fd < 0) {
        fprintf(stderr, "Unable to open map %s, err(%d): %s",
            pathname, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    int idx = 0;
    unsigned long long val = 195 * (1ULL << 32) + 0;
    unsigned int major = val >> 32;
    unsigned int minor = (unsigned int) val;
    printf("major %d minor %d\n", major, minor);
    int ret = bpf_map_update_elem(fd, &idx, &val, BPF_ANY);
    if(ret != 0) {
        fprintf(stderr, "Unable to update map %s index %d, err(%d): %s",
            pathname, idx, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
}