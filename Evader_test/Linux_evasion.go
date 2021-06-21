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
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// edode : true = sandbox; false = user

const (
	BLKGETSIZE64 		= 0x80081272
)
var (
	sandbox_files           = []string{
		// edode : according to https://evasions.checkpoint.com/techniques/filesystem.html#check-if-specific-files-exist

		// VMware
		"drivers\\vmsrvc.sys",
		"drivers\\vpc-s3.sys",
		"drivers\\vmmouse.sys",
		"drivers\\vmnet.sys",
		"drivers\\vmxnet.sys",
		"drivers\\vmhgfs.sys",
		"drivers\\vmx86.sys",
		"drivers\\hgfs.sys",

		// VirtualBox
		"drivers\\VBoxMouse.sys",
		"drivers\\VBoxGuest.sys",
		"drivers\\VBoxSF.sys",
		"drivers\\VBoxVideo.sys",
		"vboxdisp.dll",
		"vboxhook.dll",
		"vboxmrxnp.dll",
		"vboxogl.dll",
		"vboxoglarrayspu.dll",
		"vboxoglcrutil.dll",
		"vboxoglerrorspu.dll",
		"vboxoglfeedbackspu.dll",
		"vboxoglpackspu.dll",
		"vboxoglpassthroughspu.dll",
		"vboxservice.exe",
		"vboxtray.exe",
		"VBoxControl.exe",

		// Parallels
		"drivers\\prleth.sys",
		"drivers\\prlfs.sys",
		"drivers\\prlmouse.sys",
		"drivers\\prlvideo.sys",
		"drivers\\prltime.sys",
		"drivers\\prl_pv32.sys",
		"drivers\\prl_paravirt_32.sys",
	}
	sandbox_mac_addresses 	= []string {
		"08:00:27", // VMWare
		"00:0C:29", // VMWare
		"00:1C:14", // VMWare
		"00:50:56", // VMWare
		"00:05:69", // VMWare
		"08:00:27", // VirtualBox
		"00:16:3E", // Xensources
		"00:1C:42", // Parallels
		"00:03:FF", // Microsoft
		"F0:1F:AF", // Dell
	}
	sandbox_hostname 		= []string {
		"Sandbox",
		"Cuckoo",
		"Maltest",
		"Malware",
		"malsand",
		"ClonePC",
		"Fortinet",
		"Fortisandbox",
		"VIRUS",
	}
)

type memStatusEx struct {
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	unused       [6]uint64
}

func is_dir(path string)(bool){
	name := path
	fi, err := os.Stat(name)
	if err != nil { return true }
	if fi.IsDir() {	return false }
	return false
}

func get_drives() (r []string){
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ"{
		f, err := os.Open(string(drive)+":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
}

func is_connected() (bool) {
	_, err := http.Get("http://1.1.1.1")
	if err == nil { return true }
	return false
}

func get_ntp_time() (time.Time) {
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

func get_disk_size(fd uintptr, request, argp uintptr) (err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		err = errno
	}
	return os.NewSyscallError("ioctl", err)
}

func evade_disk_size()(bool){
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
	if err != nil {}

	for _, f := range(files){
		disk, err := os.Open("/dev/"+f.Name())
		if err != nil {
			continue
		}
		defer disk.Close()

		var size uint64
		if err := get_disk_size(disk.Fd(), BLKGETSIZE64, uintptr(unsafe.Pointer(&size))); err != nil {
			continue
		}

		if (size/1024/1024/1024)%100 == 0{
			return true
		}
	}
	return false
}

func evade_vm_files()(bool, int){
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
	for _, drives := range (get_drives()){
		for _, files := range(sandbox_files){
			if !is_dir(drives+":\\Windows\\System32\\" + files){
				files_detected++
			}
		}
	}
	if files_detected > 0 { return true, files_detected }
	return false, files_detected
}

func evade_tmp() (bool) {
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

	if len(files) < minimum_files { return true }
	return false
}

func evade_utc() (bool) {
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
	if offset == 0 { return true }
	return false
}

func evade_time_acceleration() (bool) {
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

	if is_connected(){
		first_time := get_ntp_time()
		time.Sleep(time.Duration(idle_time*1000) * time.Millisecond)

		second_time := get_ntp_time()
		difference := second_time.Sub(first_time).Seconds()

		if difference < float64(idle_time) { return true }
	} else {
		first_time := time.Now()
		time.Sleep(time.Duration(idle_time*1000) * time.Millisecond)
		second_time := time.Since(first_time)

		if time.Duration(second_time).Seconds() < float64(idle_time){ return true }
	}
	return false
}

func evade_cpu_count()(bool){
	if runtime.NumCPU() <= 2 {
		return true
	}
	return false
}

func evade_mac()(bool){
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
	for _, s:= range sandbox_mac_addresses {
		for _, a := range as {
			str := strings.ToUpper(a)
			if str[0:8] == s[0:8] {
				is_vm = true
			}
		}
	}
	if is_vm { return true }
	return false
}

func evade_hostname()(bool){
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
	for _, host := range(sandbox_hostname){
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return true;
		}
	}
	return false;
}

func passed(evading_func string)(){
	fmt.Println("[+] Evaded ", evading_func, "\n")
}

func failed(evading_func string)(){
	fmt.Println("[-] Not Evaded ", evading_func, "\n")
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









