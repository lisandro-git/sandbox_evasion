package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"log"
	"math"
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

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	kernel_32               = syscall.MustLoadDLL("kernel32.dll")
	getSystemMetrics        = user32.NewProc("GetSystemMetrics")
	GetDiskFreeSpaceExW     = kernel_32.MustFindProc("GetDiskFreeSpaceExW")
	globalMemoryStatusEx, _ = kernel_32.FindProc("GlobalMemoryStatusEx")
	getAsyncKeyState        = user32.NewProc("GetAsyncKeyState")
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
	sandbox_mac_addresses = []string{
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
	sandbox_hostname = []string{
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

func get_window(funcName string) uintptr {
	proc := user32.NewProc(funcName)
	hwnd, _, _ := proc.Call()
	return hwnd
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
		for _, files := range sandbox_files {
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

func evade_screen_size() bool {
	/*
		Purpose :
			Detects the screen size
		source :
			- https://stackoverflow.com/a/48187712
		linked variable :
			- getSystemMetrics
			- user32
		linked functions :
			-
	*/
	index_x := uintptr(0)
	index_y := uintptr(1)
	x, _, _ := getSystemMetrics.Call(index_x)
	y, _, _ := getSystemMetrics.Call(index_y)
	if x < 1024 || y < 768 {
		return true
	}
	return false
}

func evade_foreground_window() bool {
	/*
		Purpose :
			Detects if the user as changed window in the last 60 seconds
		source :
			- https://gist.github.com/obonyojimmy/d6b263212a011ac7682ac738b7fb4c70
		linked variables :
			- user32
		linked functions :
			- get_window
	*/
	var temp uintptr
	for i := 0; i <= 20; i++ {
		if hwnd := get_window("GetForegroundWindow"); hwnd != 0 {
			if hwnd != temp && temp != 0 {
				return true
			}
			temp = hwnd
		}
		time.Sleep(time.Second * 10)
	}
	return false
}

func evade_disk_size() bool {
	/*
		Purpose :
			Checks the system's storage space
		source :
			-
		linked variable :
			- kernel_32
			- GetDiskFreeSpaceExW
		linked functions :
			-
	*/
	var free, total, avail int64

	path_pointer, _ := syscall.UTF16PtrFromString("C:\\")
	GetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(path_pointer)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&avail)),
	)

	total_disk_size := total / 1024 / 1024 / 1024

	var i int64 = 0
	for ; i < 500; i = i + 10 {
		if i == total_disk_size {
			return true
		}
	}
	return false
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
	tmp_dir := `C:\windows\temp`
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

func evade_system_memory() bool {
	/*
		Purpose :
			checking the system's RAM memory
		source :
			- https://github.com/pbnjay/memory/blob/master/memory_windows.go
		linked variable :
			- memStatusEx (struct)
		linked functions :
			-
	*/
	msx := &memStatusEx{dwLength: 64}
	r, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(msx)))
	if r == 0 {
		return false
	}

	system_memory := float64(msx.ullTotalPhys/1024/1024) / 1024

	if int(math.Ceil(system_memory))%2 == 1 || system_memory <= 2 {
		return true
	}
	return false
}

func evade_printer() bool {
	/*
		Purpose :
			Checks wether a printer has been installed in the machine
		source :
			-
		linked variable :
			-
		linked functions :
			-
	*/
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Print\Printers`, registry.QUERY_VALUE)
	if err != nil {
		key.Close()
		return true
	}
	defer key.Close()

	key_stat, err := key.Stat()
	if err != nil {
		return true
	}

	if key_stat.SubKeyCount <= 3 {
		return true
	}
	return false
}

func evade_cpu_count() bool {
	if runtime.NumCPU() <= 2 {
		return true
	}
	return false
}

func evade_clicks_count() bool {
	/*
		Purpose :
			Checks if there is any user clicks
		source :
			- https://github.com/Arvanaghi/CheckPlease/blob/master/Go/click_tracker.go
		linked variables :
			- user32
			- getAsyncKeyState
		linked functions :
			-
	*/
	var count int
	var max_idle_time = 120
	t := time.Now()
	for count <= 10 {
		left_click, _, _ := getAsyncKeyState.Call(uintptr(0x1))
		right_click, _, _ := getAsyncKeyState.Call(uintptr(0x2))
		if left_click%2 == 1 {
			count += 1
			t = time.Now()
		}
		if right_click%2 == 1 {
			count += 1
			t = time.Now()
		}
		if int(time.Since(t).Seconds()) > max_idle_time {
			return true
		}
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
	for _, s := range sandbox_mac_addresses {
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
	for _, host := range sandbox_hostname {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return true
		}
	}
	return false
}

func main() {

}
