/*
Nvidia container hook usurper: calls the upstream nvidia-container-hook
*/
package main

// Inspired from https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvcgo/internal/cgroup/ebpf.go
import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/akamensky/argparse"
)

func main() {

	log.Println("NVIDIA HOOK USURPER")

	if len(os.Args) < 2 {
		log.Panic("Nothing but the container-cli bin provided, " +
			"missing cmdline params!")
	}

	cmd := exec.Command(
		"/usr/bin/nvidia-container-cli", os.Args[1:]...)

	out, err := cmd.Output()
	if err != nil {
		// if there was any error, print it here
		log.Panicf("Could not run command:\ncmd: %s\ndetails: %v",
			cmd, err)
	}
	// otherwise, print the output from running the command
	log.Println("Output: ", string(out))

	//env := strings.ToLower(os.Getenv("ZERO_GPU"))

	parser := argparse.NewParser("nvidia-container-hook", "nvidia-container-hook")

	// Create string flag
	a := parser.String("s", "string", &argparse.Options{Required: true, Help: "String to print"})
	fmt.Printf("%s", a)
	// parser := flag.Parse()
	// args, _ := parser.Parse()
	// if (env == "true") || (env == "1") {
	// 	log.Println("Getting container pid")
	// 	for _, a := range os.Args[1:] {
	// 		if a == '-p'
	// 	}
	// 	cmd :=
	// }

}
