package main

import (
	"log"
	"net"
	"os"
	"strings"
)

// edode : if a value returns "true", this means that the code is running in a sandbox

var sandbox_mac_addresses = []string{
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

var sandbox_hostname = []string{
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
