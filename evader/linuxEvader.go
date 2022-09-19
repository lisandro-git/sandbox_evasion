package evader

import (
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
