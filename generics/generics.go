package generics

var (
	SandboxFiles = []string{
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
	SandboxMacAddresses = []string{
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
	SandboxHostname = []string{
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
