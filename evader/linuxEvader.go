package evader

import (
	"fmt"
	"os"
	"syscall"
)

// edode : true = sandbox; false = user

const (
	BLKGETSIZE64 = 0x80081272
)

func getDiskSize(fd uintptr, request, argp uintptr) (err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		err = errno
	}
	return os.NewSyscallError("ioctl", err)
}

func ExecuteAll() {
	fmt.Println(("Evading Tmp"))
	if !evadeTmp() {
		passed("tmp")
	} else {
		failed("tmp")
	}
	fmt.Println(("Evading UTC"))
	if !evadeUtc() {
		passed("UTC")
	} else {
		failed("UTC")
	}
	fmt.Println(("Evading CPU Count"))
	if !evadeCpuCount() {
		passed("cpu_count")
	} else {
		failed("cpu_count")
	}
	fmt.Println(("Evading MAC"))
	if !evadeMac() {
		passed("MAC")
	} else {
		failed("MAC")
	}
	fmt.Println(("Evading Hostname"))
	if !evadeHostname() {
		passed("evadeHostname")
	} else {
		failed("evadeHostname")
	}
	fmt.Println(("Evading Disk Size"))
	if !evadeDiskSize() {
		passed("disk_size")
	} else {
		failed("disk_size")
	}
	fmt.Println(("Evading VM Files"))
	b, _ := evadeVmFiles()
	if !b {
		passed("vm_files")
	} else {
		failed("vm_files")
	}
	fmt.Println(("Evading Time Acceleration"))
	if !evadeTimeAcceleration() {
		passed("Time Acceleration")
	} else {
		failed("Time Acceleration")
	}
	fmt.Scanln("Done...")
}
