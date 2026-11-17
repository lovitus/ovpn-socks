//go:build windows

package config

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	advapi      = syscall.NewLazyDLL("advapi32.dll")
	convertSD   = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	setSecurity = advapi.NewProc("SetFileSecurityW")
	localFree   = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

// securePath replaces the DACL, disables inherited access, and allows only
// the current token user and LocalSystem. Directories propagate these rights.
func securePath(path string, directory bool) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	var descriptor uintptr
	ok, _, callErr := convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return fmt.Errorf("create private ACL: %w", callErr)
	}
	defer localFree.Call(descriptor)
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
	ok, _, callErr = setSecurity.Call(uintptr(unsafe.Pointer(name)), 0x80000004, descriptor)
	if ok == 0 {
		return fmt.Errorf("apply private ACL: %w", callErr)
	}
	return os.Chmod(path, 0600)
}

// Windows file Sync flushes the contents before MoveFileEx atomically replaces
// the destination. Windows does not support syncing a directory via os.File.
func syncDirectory(string) error { return nil }
