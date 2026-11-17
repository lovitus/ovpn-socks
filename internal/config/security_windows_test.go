//go:build windows

package config

import (
	"path/filepath"
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
	descriptorString := func(descriptor uintptr) string {
		t.Helper()
		var text *uint16
		var length uint32
		ok, _, callErr := stringify.Call(descriptor, 1, 4, uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)))
		if ok == 0 {
			t.Fatal(callErr)
		}
		defer localFree.Call(uintptr(unsafe.Pointer(text)))
		return syscall.UTF16ToString(unsafe.Slice(text, length))
	}
	canonicalSDDL := func(sddl string) string {
		t.Helper()
		encoded, err := syscall.UTF16PtrFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		var descriptor uintptr
		ok, _, callErr := convertSD.Call(uintptr(unsafe.Pointer(encoded)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
		if ok == 0 {
			t.Fatal(callErr)
		}
		defer localFree.Call(descriptor)
		return descriptorString(descriptor)
	}
	for i, path := range []string{dir, filepath.Join(dir, keyFile), filepath.Join(dir, dataFile)} {
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
		sddl := descriptorString(uintptr(unsafe.Pointer(&buffer[0])))
		inherit := ""
		if i == 0 {
			inherit = "OICI"
		}
		// Windows may render a full SID as an SDDL alias (for example, the
		// runner's local administrator SID as LA). Canonicalize the expected
		// descriptor through the same API, then compare the complete DACL:
		// protection, inheritance, rights and exactly these two trustees.
		want := canonicalSDDL("D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;" + sid + ")")
		if sddl != want {
			t.Fatalf("unexpected ACL for %s: got %s, want %s", path, sddl, want)
		}
	}
}
