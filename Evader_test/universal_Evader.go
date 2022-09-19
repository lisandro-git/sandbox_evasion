package main

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

func is_dir(path string) bool {
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

func get_drives() (r []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
}

func is_connected() bool {
	_, err := http.Get("http://1.1.1.1")
	if err == nil {
		return true
	}
	return false
}

func get_ntp_time() time.Time {
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

func get_mac_address() ([]string, error) {
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

func evade_disk_size() bool {
	/*
		Purpose :
			Checks the system's storage space
		source :
			-
		linked variable :
			- BLKGETSIZE64
		linked functions :
			- get_disk_size
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
		if err := get_disk_size(disk.Fd(), BLKGETSIZE64, uintptr(unsafe.Pointer(&size))); err != nil {
			continue
		}

		if (size/1024/1024/1024)%100 == 0 {
			return true
		}
	}
	return false
}

func evade_vm_files() (bool, int) {
	/*
		Purpose :
			Checks a VM file is present on the system
		source :
			-
		linked variables :
			- sandbox_files
		linked functions :
			- get_drives
			- is_dir
	*/
	var files_detected int
	for _, drives := range get_drives() {
		for _, files := range generics.SandboxFiles {
			if !is_dir(drives + ":\\Windows\\System32\\" + files) {
				files_detected++
			}
		}
	}
	if files_detected > 0 {
		return true, files_detected
	}
	return false, files_detected
}

func evade_tmp() bool {
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
	minimum_files := 15
	tmp_dir := "/tmp"
	files, _ := ioutil.ReadDir(tmp_dir)

	if len(files) < minimum_files {
		return true
	}
	return false
}

func evade_utc() bool {
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

func evade_time_acceleration() bool {
	/*
		Purpose :
			Malware stays idl for a certain amount of time to evade the sandbox
		source :
			-
		linked variable :
			-
		linked functions :
			- get_ntp_time
			- is_connected
	*/
	idle_time := 60

	if is_connected() {
		first_time := get_ntp_time()
		time.Sleep(time.Duration(idle_time*1000) * time.Millisecond)

		second_time := get_ntp_time()
		difference := second_time.Sub(first_time).Seconds()

		if difference < float64(idle_time) {
			return true
		}
	} else {
		first_time := time.Now()
		time.Sleep(time.Duration(idle_time*1000) * time.Millisecond)
		second_time := time.Since(first_time)

		if time.Duration(second_time).Seconds() < float64(idle_time) {
			return true
		}
	}
	return false
}

func evade_cpu_count() bool {
	if runtime.NumCPU() <= 2 {
		return true
	}
	return false
}

func evade_mac() bool {
	/*
		source :
			- https://search.unprotect.it/technique/detecting-mac-address/
		linked variables :
			- sandbox_mac_addresses
		linked functions :
			- get_mac_address
	*/
	as, err := get_mac_address()
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

func evade_hostname() bool {
	/*
		source :
			- https://github.com/Arvanaghi/CheckPlease/blob/master/Go/hostname.go
		linked variables :
			- sandbox_hostname
		linked functions :
			-
	*/
	hostname, errorout := os.Hostname()
	if errorout != nil {
		os.Exit(1)
	}
	for _, host := range generics.SandboxHostname {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return true
		}
	}
	return false
}

func passed(evading_func string) {
	fmt.Println("[+] Evaded ", evading_func)
}

func failed(evading_func string) {
	fmt.Println("[-] Not Evaded ", evading_func)
}
