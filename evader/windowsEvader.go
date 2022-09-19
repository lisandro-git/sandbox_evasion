package evader

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"math"
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
)

func getWindow(funcName string) uintptr {
	proc := user32.NewProc(funcName)
	hwnd, _, _ := proc.Call()
	return hwnd
}

func evadeScreenSize() bool {
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
	fmt.Println("X = ", x, " Y = ", y)
	if x < 1024 || y < 768 {
		return true
	}
	return false
}

func evadeForegroundWindow() bool {
	/*
		Purpose :
			Detects if the user as changed window in the last 60 seconds
		source :
			- https://gist.github.com/obonyojimmy/d6b263212a011ac7682ac738b7fb4c70
		linked variables :
			- user32
		linked functions :
			- getWindow
	*/
	var temp uintptr
	for i := 0; i <= 20; i++ {
		if hwnd := getWindow("GetForegroundWindow"); hwnd != 0 {
			if hwnd != temp && temp != 0 {
				return true
			}
			temp = hwnd
		}
		time.Sleep(time.Second * 10)
	}
	return false
}

func evadeSystemMemory() bool {
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
	fmt.Println("System memory = ", system_memory)
	if int(math.Ceil(system_memory))%2 == 1 || system_memory <= 2 {
		return true
	}
	return false
}

func evadePrinter() bool {
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
	fmt.Println("Subkey count = ", key_stat.SubKeyCount)
	if key_stat.SubKeyCount <= 3 {
		return true
	}
	return false
}

func evadeClicksCount() bool {
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
	var maxIdleTime = 120
	t := time.Now()
	for count <= 10 {
		leftClick, _, _ := getAsyncKeyState.Call(uintptr(0x1))
		rightClick, _, _ := getAsyncKeyState.Call(uintptr(0x2))
		if leftClick%2 == 1 {
			count += 1
			t = time.Now()
		}
		if rightClick%2 == 1 {
			count += 1
			t = time.Now()
		}
		if int(time.Since(t).Seconds()) > maxIdleTime {
			return true
		}
	}
	return false
}
