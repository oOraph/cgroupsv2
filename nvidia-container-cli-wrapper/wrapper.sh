#!/bin/bash

set -ex -o pipefail -u

exit_trap () {
  local lc="$BASH_COMMAND" rc=$?
  echo "Nvidia container cli wrapper failed. [$lc] exited with code [$rc]" | tee >&2
}

trap exit_trap EXIT
{
    echo "Calling nvidia container cli wrapper"
    echo "$@"

    echo Identifying target pid
    p=$(echo $(echo "$@" | grep -oP '\s+(-p|--pid)(=|\s+)\K(\d+)(\s|$)'))

    echo Container pid $p

    cgroupPath=/sys/fs/cgroup/$(cat /proc/$p/cgroup | grep -oP '^\d+::/\K.*')

    echo Cgroup path $cgroupPath

    /usr/bin/nvidia-container-cli.real $@

    gpuacl $cgroupPath
} > /tmp/log1.log 2>/tmp/log1.err