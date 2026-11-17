//go:build windows

package config

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestWindowsPrivateACL(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(sampleProfile()); err != nil {
		t.Fatal(err)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	getSecurity := advapi.NewProc("GetFileSecurityW")
	stringify := advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	for _, path := range []string{dir, filepath.Join(dir, keyFile), filepath.Join(dir, dataFile)} {
		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		var needed uint32
		ok, _, callErr := getSecurity.Call(uintptr(unsafe.Pointer(name)), 4, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&needed)))
		if ok == 0 {
			t.Fatal(callErr)
		}
		var text *uint16
		var length uint32
		ok, _, callErr = stringify.Call(uintptr(unsafe.Pointer(&buffer[0])), 1, 4, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)))
		if ok == 0 {
			t.Fatal(callErr)
		}
		sddl := syscall.UTF16ToString(unsafe.Slice(text, length))
		localFree.Call(uintptr(unsafe.Pointer(text)))
		if !strings.HasPrefix(sddl, "D:P") || strings.Count(sddl, "(A;") != 2 || !strings.Contains(sddl, ";;;SY)") || !strings.Contains(sddl, ";;;"+sid+")") {
			t.Fatalf("unexpected ACL for %s: %s", path, sddl)
		}
	}
}
