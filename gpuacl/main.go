/*
Allow/deny gpu access to specified cgroups, ignore other devices
and let them pass other device filters if any at all
*/
package main

// Inspired from https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvcgo/internal/cgroup/ebpf.go
import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

var GpuMajor int32 = 195
var NvidiaModesetMinor int32 = 254
var NvidiaCtlMinor int32 = 255

const (
	BpfProgramLicense = "GPL"
)

const (
	AcceptDevice  string = "acceptdevice"
	DenyDevice           = "denydevice"
	DeviceFilters        = "devicefilters"
)

type program struct {
	name  string
	insts asm.Instructions
	label string
}

func (p *program) init() {
	// struct bpf_cgroup_dev_ctx: https://elixir.bootlin.com/linux/v5.3.6/source/include/uapi/linux/bpf.h#L3423
	// access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*
	// upper half word rwm perms, lower half word device type
	/*
		u32 access_type
		u32 major
		u32 minor
	*/

	log.Infof("Initializing the bpf program")

	p.label = uuid.New().String()

	// R2 <- type (lower 16 bit of u32 access_type at R1[0])
	p.insts = append(p.insts,
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Half))

	// R3 <- access (upper 16 bit of u32 access_type at R1[0])
	p.insts = append(p.insts,
		asm.LoadMem(asm.R3, asm.R1, 0, asm.Word),
		// RSh: bitwise shift right
		asm.RSh.Imm32(asm.R3, 16))

	// R4 <- major (u32 major at R1[4])
	p.insts = append(p.insts,
		asm.LoadMem(asm.R4, asm.R1, 4, asm.Word))

	// R5 <- minor (u32 minor at R1[8])
	p.insts = append(p.insts,
		asm.LoadMem(asm.R5, asm.R1, 8, asm.Word))

	// // R6 <- 0 for unconditional jump below
	// p.insts = append(p.insts, asm.Xor.Reg(asm.R6, asm.R6))

	// // Jump past Accept/Deny below...
	// p.insts = append(p.insts, asm.JEq.Imm32(asm.R6, 0, p.programSymbol(DeviceFilters)))

	// Not a char device just accept, not our business let other bpf filters handle them
	p.insts = append(p.insts, asm.JNE.Imm(asm.R2, int32(unix.BPF_DEVCG_DEV_CHAR), p.programSymbol(AcceptDevice)))
	// p.addSymbolToInstruction(DeviceFilters, 1)

	// Major != 195, not our business, accept
	p.insts = append(p.insts, asm.JNE.Imm(asm.R4, GpuMajor, p.programSymbol(AcceptDevice)))

	// From then on we're dealing with char devices whose major is 195

	// Mknod permission requested, no way, let's recycle R2 as we won't need the device type anymore
	// as we now know it's a char device
	mknodAccess := int32(unix.BPF_DEVCG_ACC_MKNOD)
	p.insts = append(p.insts, asm.Mov.Reg32(asm.R2, asm.R3))
	p.insts = append(p.insts, asm.And.Imm32(asm.R2, mknodAccess))
	p.insts = append(p.insts,
		asm.JNE.Imm(asm.R2, 0, p.programSymbol(DenyDevice)))

	// Minor == 255, accept
	p.insts = append(p.insts, asm.JEq.Imm(asm.R5, NvidiaCtlMinor, p.programSymbol(AcceptDevice)))

	// Minor == 254, accept
	p.insts = append(p.insts, asm.JEq.Imm(asm.R5, NvidiaModesetMinor, p.programSymbol(AcceptDevice)))

	// Now we know that we are dealing with gpu access request and with rw access requests only
	// Now program is initialized ready to accept any specified gpu and deny any others
}

func (p *program) programSymbol(symbol string) string {
	return fmt.Sprintf("%s-%s", p.label, symbol)
}

func (p *program) addSymbolToInstruction(symbol string, offset int) {
	symbol = p.programSymbol(symbol)
	p.insts[len(p.insts)-offset] = p.insts[len(p.insts)-offset].WithSymbol(symbol)
}

func (p *program) allowGPU(gpuMinor uint32) {
	p.insts = append(p.insts, asm.JEq.Imm(asm.R5, int32(gpuMinor), p.programSymbol(AcceptDevice)))
}

func (p *program) finalize() {
	log.Infof("Finalizing the bpf program")

	// Deny device, default
	p.insts = append(p.insts, p.stateOnDevice(false)...)
	p.addSymbolToInstruction(DenyDevice, 2)

	// Accept device
	p.insts = append(p.insts, p.stateOnDevice(true)...)
	p.addSymbolToInstruction(AcceptDevice, 2)

	log.Infof("Insts %v", p.insts)
}

func (p *program) stateOnDevice(accept bool) asm.Instructions {
	v := int32(0)
	if accept {
		v = 1
	}
	return []asm.Instruction{
		// R0 <- v
		asm.Mov.Imm32(asm.R0, v),
		asm.Return(),
	}
}

func (p *program) reload(cgroupPath string) error {
	log.Infof("Reloading custom bpf program for cgroup %s", cgroupPath)

	cgroupFD, err := unix.Open(cgroupPath, unix.O_DIRECTORY|unix.O_RDONLY, 0600)
	if err != nil {
		log.Errorf("Unable to open the cgroup path %s: %v", cgroupPath, err)
		return err
	}
	defer unix.Close(cgroupFD)

	// Step 1 list all programs attached to this cgroup with the same name: programs to be removed
	log.Info("Listing all bpf programs to be removed")
	toRm, err := p.listAttachedPrograms(cgroupFD)
	if err != nil {
		log.Errorf("Unable to list cgroup bpf attached programs, skipping. Details %v", err)
		return err
	}

	log.Infof("Found %d programs with name %s attached to cgroup %s",
		len(toRm), p.name, cgroupPath)

	// Step 2: load
	log.Info("Loading new bpf program")
	spec := ebpf.ProgramSpec{
		Name:         p.name,
		Type:         ebpf.CGroupDevice,
		License:      BpfProgramLicense,
		Instructions: p.insts,
	}
	o, err := ebpf.NewProgram(&spec)
	if err != nil {
		log.Errorf("Unable to load bpf cgroupdev program %s ! %v", p.name, err)
		return err
	}

	// Step 3: attach
	log.Infof("Attaching program to cgroup %d", cgroupFD)
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: o,
		Attach:  ebpf.AttachCGroupDevice,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	})
	if err != nil {
		log.Errorf("Failed to call BPF_PROG_ATTACH (BPF_CGROUP_DEVICE, BPF_F_ALLOW_MULTI): %v", err)
		return err
	}

	// Step 4: detach any program with the same name already attached to cgroup that is not this program
	log.Infof("Detaching old programs from cgroup %s", cgroupPath)
	for _, prgm := range toRm {
		err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  cgroupFD,
			Program: prgm,
			Attach:  ebpf.AttachCGroupDevice,
		})
		if err != nil {
			log.Errorf("Failed to call BPF_PROG_DETACH (BPF_CGROUP_DEVICE): %v", err)
			return err
		}
	}
	return nil
}

// Adapted from https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvcgo/internal/cgroup/ebpf.go
// FindAttachedCgroupDeviceFilters finds all ebpf prgrams
// associated with 'cgroupFD' that control device access
// We only consider the programs with the same name as the one we are currently building
func (p *program) listAttachedPrograms(cgroupFD int) ([]*ebpf.Program, error) {
	type bpfAttrQuery struct {
		TargetFd    uint32
		AttachType  uint32
		QueryType   uint32
		AttachFlags uint32
		ProgIds     uint64 // __aligned_u64
		ProgCnt     uint32
	}

	// Currently you can only have 64 eBPF programs attached to a cgroup.
	size := 64
	retries := 0
	for retries < 10 {
		progIDs := make([]uint32, size)
		query := bpfAttrQuery{
			TargetFd:   uint32(cgroupFD),
			AttachType: uint32(unix.BPF_CGROUP_DEVICE),
			ProgIds:    uint64(uintptr(unsafe.Pointer(&progIDs[0]))),
			ProgCnt:    uint32(len(progIDs)),
		}

		// Fetch the list of program ids.
		_, _, errno := unix.Syscall(unix.SYS_BPF,
			uintptr(unix.BPF_PROG_QUERY),
			uintptr(unsafe.Pointer(&query)),
			unsafe.Sizeof(query))
		size = int(query.ProgCnt)
		runtime.KeepAlive(query)
		if errno != 0 {
			// On ENOSPC we get the correct number of programs.
			if errno == unix.ENOSPC {
				retries++
				continue
			}
			return nil, fmt.Errorf("bpf_prog_query(BPF_CGROUP_DEVICE) failed: %w", errno)
		}

		// Convert the ids to program handles.
		progIDs = progIDs[:size]
		programs := make([]*ebpf.Program, 0, len(progIDs))
		for _, progID := range progIDs {
			program, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
			if err != nil {
				// We skip over programs that give us -EACCES or -EPERM. This
				// is necessary because there may be BPF programs that have
				// been attached (such as with --systemd-cgroup) which have an
				// LSM label that blocks us from interacting with the program.
				//
				// Because additional BPF_CGROUP_DEVICE programs only can add
				// restrictions, there's no real issue with just ignoring these
				// programs (and stops runc from breaking on distributions with
				// very strict SELinux policies).
				if errors.Is(err, os.ErrPermission) {
					log.Infof("ignoring existing CGROUP_DEVICE program (prog_id=%v) which cannot be accessed by runc -- likely due to LSM policy: %v", progID, err)
					continue
				}
				return nil, fmt.Errorf("cannot fetch program from id: %w", err)
			}

			info, err := program.Info()
			if err != nil {
				log.Warn("Unable to gather ebpf program info, skipping")
				continue
			}
			name := info.Name
			log.Infof(
				"Found ebpf program %s attached to cgroup with fd %d", name, cgroupFD)
			if name == p.name {
				programs = append(programs, program)
			}
		}
		runtime.KeepAlive(progIDs)
		return programs, nil
	}

	return nil, errors.New("could not get complete list of CGROUP_DEVICE programs")
}

func main() {
	if len(os.Args) < 2 {
		log.Panicf("Missing mandatory cgroup path")
	}

	argv := os.Args[1:]

	cgroupPath := argv[0]
	re := regexp.MustCompile(`/+`)
	cgroupPath = re.ReplaceAllString(cgroupPath, "/")
	if len(cgroupPath) > 0 && (cgroupPath[len(cgroupPath)-1:] == "/") {
		cgroupPath = cgroupPath[0 : len(cgroupPath)-1]
	}

	indexesLen := len(argv) - 1
	indexes := make([]uint32, 0, indexesLen)
	if indexesLen > 0 {
		for _, idxstr := range argv[1:] {
			idx, err := strconv.Atoi(idxstr)
			if err != nil {
				log.Panicf("Provided arg %v is not an integer !", idxstr)
			}
			if idx < 0 {
				log.Panicf("Gpu indexes must be positive (%d provided) !", idx)
			}
			indexes = append(indexes, uint32(idx))
		}
	}
	hash := md5.Sum([]byte(cgroupPath))
	prgmName := "gpuacl" + hex.EncodeToString(hash[:])[0:8]
	prgm := program{
		name: prgmName,
	}
	prgm.init()
	for _, idx := range indexes {
		prgm.allowGPU(idx)
	}
	prgm.finalize()
	err := prgm.reload(cgroupPath)
	if err != nil {
		log.Panicf("err %v", err)
	}
}
