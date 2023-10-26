On ubuntu, install example

Dependencies

libelf-dev
zlib-dev
llvm
clang
gcc-multilib
build-essential

Bpftool program
Available in the linux-tools-* packages related to the running kernel


# Build

```
$ cd gpu_deny
$ make all
```

# What this program does

Allow access to anything that is not an nvidia gpu device
Only allow access to gpu specified in the map (up to 10 entries = GPU can be allowed)

# Usage

## Load BPF program

```
$ bpftool prog load ./build/gpu_deny.o /sys/fs/bpf/gpu_deny type cgroup/dev
```

This automatically creates the cgroup/dev bpf program called gpu_deny. This program is exported in the BPF pseudo fs: this is done so to keep a fake reference to the program: bpf dangling programs are automatically unloaded and since we just load the program with bpftool without attaching it to any cgroup, the program would not be kept.

The program initializes an array map alongside the program, called gpu_deny_map

For the map to be used in userland, it must be exported for example in the BPF pseudo-fs, the same way the program was previously pinned when loaded. A.k.a map pining

```
$ bpftool map pin name gpu_deny_map /sys/fs/bpf/gpu_deny_map
```

## Attach the program to one cgroup, in multi mode

```
$ bpftool cgroup attach /sys/fs/cgroup/mycgroup1/ cgroup_device name gpu_deny multi
```

## Update the map

Run the userland program

TODO: allowed device is hardcoded for now as a PoC, make it more dynamic

```
$ ./build/gpu_selector
```

## Cleanup everything

```
bpftool cgroup detach /sys/fs/cgroup/mycgroup1/ cgroup_device name gpu_deny multi
rm -f /sys/fs/bpf/gpu_deny /sys/fs/bpf/gpu_deny_map
```

# Known issues

If we want to attach the program to several cgroups, we'd like them to have individual maps per cgroup, currently not possible
