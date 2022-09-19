package evader

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sandboxEvasion/generics"
	"strings"
	"time"
	"unsafe"
)

type memStatusEx struct {
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	unused       [6]uint64
}

func isDir(path string) bool {
	name := path
	fi, err := os.Stat(name)
	if err != nil {
		return true
	}
	if fi.IsDir() {
		return false
	}
	return false
}

func getDrives() (r []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
}

func isConnected() bool {
	_, err := http.Get("http://1.1.1.1")
	if err == nil {
		return true
	}
	return false
}

func getNtpTime() time.Time {
	type ntp struct {
		FirstByte, A, B, C uint8
		D, E, F            uint32
		G, H               uint64
		ReceiveTime        uint64
		J                  uint64
	}
	sock, _ := net.Dial("udp", "us.pool.ntp.org:123")
	sock.SetDeadline(time.Now().Add((2 * time.Second)))
	defer sock.Close()
	transmit := new(ntp)
	transmit.FirstByte = 0x1b
	binary.Write(sock, binary.BigEndian, transmit)
	binary.Read(sock, binary.BigEndian, transmit)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(((transmit.ReceiveTime >> 32) * 1000000000)))
}

func getMacAddress() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}

func evadeDiskSize() bool {
	/*
		Purpose :
			Checks the system's storage space
		source :
			-
		linked variable :
			- BLKGETSIZE64
		linked functions :
			- getDiskSize
	*/
	files, err := ioutil.ReadDir("/sys/block")
	if err != nil {
	}

	for _, f := range files {
		disk, err := os.Open("/dev/" + f.Name())
		if err != nil {
			continue
		}
		defer disk.Close()

		var size uint64
		if err := getDiskSize(disk.Fd(), BLKGETSIZE64, uintptr(unsafe.Pointer(&size))); err != nil {
			continue
		}

		if (size/1024/1024/1024)%100 == 0 {
			return true
		}
	}
	return false
}

func evadeVmFiles() (bool, int) {
	/*
		Purpose :
			Checks a VM file is present on the system
		source :
			-
		linked variables :
			- sandbox_files
		linked functions :
			- getDrives
			- isDir
	*/
	var filesDetected int
	for _, drives := range getDrives() {
		for _, files := range generics.SandboxFiles {
			if !isDir(drives + ":\\Windows\\System32\\" + files) {
				filesDetected++
			}
		}
	}
	if filesDetected > 0 {
		return true, filesDetected
	}
	return false, filesDetected
}

func evadeTmp() bool {
	/*
		Purpose :
			Checks if there is a minimum of temporary files in the temp folders
		source :
			-
		linked variable :
			-
		linked functions :
			-
	*/
	minimumFiles := 15
	tmpDir := "/tmp"
	files, _ := ioutil.ReadDir(tmpDir)

	if len(files) < minimumFiles {
		return true
	}
	return false
}

func evadeUtc() bool {
	/*
		Purpose :
			Checks the offset of the time zone
		source :
			-
		linked variable :
			-
		linked functions :
			-
	*/
	_, offset := time.Now().Zone()
	if offset == 0 {
		return true
	}
	return false
}

func evadeTimeAcceleration() bool {
	/*
		Purpose :
			Malware stays idl for a certain amount of time to evade the sandbox
		source :
			-
		linked variable :
			-
		linked functions :
			- getNtpTime
			- isConnected
	*/
	idleTime := 60

	if isConnected() {
		firstTime := getNtpTime()
		time.Sleep(time.Duration(idleTime*1000) * time.Millisecond)
		secondTime := getNtpTime()

		if secondTime.Sub(firstTime).Seconds() < float64(idleTime) {
			return true
		}
	} else {
		firstTime := time.Now()
		time.Sleep(time.Duration(idleTime*1000) * time.Millisecond)

		if time.Since(firstTime).Seconds() < float64(idleTime) {
			return true
		}
	}
	return false
}

func evadeCpuCount() bool {
	if runtime.NumCPU() <= 2 {
		return true
	}
	return false
}

func evadeMac() bool {
	/*
		source :
			- https://search.unprotect.it/technique/detecting-mac-address/
		linked variables :
			- sandbox_mac_addresses
		linked functions :
			- getMacAddress
	*/
	as, err := getMacAddress()
	if err != nil {
		log.Fatal(err)
	}
	var is_vm bool
	for _, s := range generics.SandboxMacAddresses {
		for _, a := range as {
			str := strings.ToUpper(a)
			if str[0:8] == s[0:8] {
				is_vm = true
			}
		}
	}
	if is_vm {
		return true
	}
	return false
}

func evadeHostname() bool {
	/*
		source :
			- https://github.com/Arvanaghi/CheckPlease/blob/master/Go/hostname.go
		linked variables :
			- sandbox_hostname
		linked functions :
			-
	*/
	hostname, err := os.Hostname()
	if err != nil {
		os.Exit(1)
	}
	for _, host := range generics.SandboxHostname {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return true
		}
	}
	return false
}

func passed(evadingFunc string) {
	fmt.Println("[+] Evaded ", evadingFunc)
}

func failed(evadingFunc string) {
	fmt.Println("[-] Not Evaded ", evadingFunc)
}
