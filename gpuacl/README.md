# Deny any GPU
./gpuacl /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podc9b08c7a_2bce_4e39_8587_9610802fca7a.slice/cri-containerd-91d73789bb3f274b6550b6831206c66476b296e6026e6d241ad3167109700257.scope

# Expose /dev/nvidia0 to cgroup
./gpuacl /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podc9b08c7a_2bce_4e39_8587_9610802fca7a.slice/cri-containerd-91d73789bb3f274b6550b6831206c66476b296e6026e6d241ad3167109700257.scope 0