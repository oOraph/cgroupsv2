/*
Nvidia container hook usurper: calls the upstream nvidia-container-hook
*/
package main

// Inspired from https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvcgo/internal/cgroup/ebpf.go
import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type HookState struct {
	Pid    int    `json:"pid"`
	Bundle string `json:"bundle"`
}

type Process struct {
	Env []string `json:"env,omitempty"`
}

type RuntimeSpec struct {
	Process *Process `json:"process,omitempty"`
}

func loadSpec(path string) (spec *RuntimeSpec) {
	// We do not extract everything, just what is of interest for us (env vars)
	f, err := os.Open(path)
	if err != nil {
		log.Panicln("could not open OCI spec:", err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(spec); err != nil {
		log.Panicln("could not decode OCI spec:", err)
	}
	if spec.Process == nil {
		log.Panicf("Process section is empty in OCI spec %v", spec)
	}
	return spec
}

func main() {
	shouldDeny := false

	log.Println("NVIDIA HOOK USURPER")

	log.Printf("Env %v\n", os.Environ())

	input, err := io.ReadAll(os.Stdin)

	if err != nil {
		log.Panicf("Unable to read from stdin properly, err %v", err)
	}

	log.Printf("Provided stdin %s\n", input)

	var state HookState
	err = json.Unmarshal(input, &state)

	if err != nil {
		log.Panicf("Unable to parse stdin into json, err %v", err)
	}

	if state.Pid <= 0 {
		log.Panicf("Unable to extract pid from stdin, pid %d", state.Pid)
	}

	if state.Bundle == "" {
		log.Println("Unable to extract bundle path from hook state, skipping " +
			"and assuming we should deny gpu devices on start")
		shouldDeny = true
	} else {
		spec := loadSpec(filepath.Join(state.Bundle, "config.json"))
		log.Printf("OCI partial spec %v", spec)
		for _, env := range spec.Process.Env {
			chunks := strings.SplitN(env, "=", 2)
			if len(chunks) < 2 {
				continue
			}
			key := chunks[0]
			value := strings.ToLower(chunks[1])
			if key == "BPF_HIDE_GPUS" && (value == "true" || value == "1") {
				shouldDeny = true
				break
			}
		}
	}

	log.Printf("Container pid %d, should be denied gpus at startup ? %t\n", state.Pid, shouldDeny)

	cmd := exec.Command("/usr/bin/nvidia-container-runtime-hook")

	if len(os.Args) >= 2 {
		cmd = exec.Command(
			"/usr/bin/nvidia-container-runtime-hook", os.Args[1:]...)
	}

	cmd.Env = os.Environ()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Panicf("Unable to get subprocess stdin ! %v", err)
	}
	defer stdin.Close()

	stdin.Write(input)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Panicf("Could not run command:\ncmd: %s\ndetails: err %v out %s",
			cmd, err, out)
	}
	// otherwise, print the output from running the command
	log.Println("Output: ", string(out))

	if shouldDeny {
		getPidCgroup(pid)
	}

	fmt.Printf("Pid to consider %d", pid)
}
