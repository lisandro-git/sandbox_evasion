package main

import (
	"fmt"
	"os"
	"syscall"
)

// edode : true = sandbox; false = user

const (
	BLKGETSIZE64 = 0x80081272
)

func get_disk_size(fd uintptr, request, argp uintptr) (err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		err = errno
	}
	return os.NewSyscallError("ioctl", err)
}

func main() {
	fmt.Println(("Evading Tmp"))
	if !evade_tmp() {
		passed("tmp")
	} else {
		failed("tmp")
	}
	fmt.Println(("Evading UTC"))
	if !evade_utc() {
		passed("UTC")
	} else {
		failed("UTC")
	}
	fmt.Println(("Evading CPU Count"))
	if !evade_cpu_count() {
		passed("cpu_count")
	} else {
		failed("cpu_count")
	}
	fmt.Println(("Evading MAC"))
	if !evade_mac() {
		passed("MAC")
	} else {
		failed("MAC")
	}
	fmt.Println(("Evading Hostname"))
	if !evade_hostname() {
		passed("evade_hostname")
	} else {
		failed("evade_hostname")
	}
	fmt.Println(("Evading Disk Size"))
	if !evade_disk_size() {
		passed("disk_size")
	} else {
		failed("disk_size")
	}
	fmt.Println(("Evading VM Files"))
	b, _ := evade_vm_files()
	if !b {
		passed("vm_files")
	} else {
		failed("vm_files")
	}
	fmt.Println(("Evading Time Acceleration"))
	if !evade_time_acceleration() {
		passed("Time Acceleration")
	} else {
		failed("Time Acceleration")
	}
	fmt.Scanln("Done...")
}
