//go:build !windows

package engine

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type processTree struct {
	mu  sync.Mutex
	pid int
}

func newProcessTree(cmd *exec.Cmd) (*processTree, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &processTree{}, nil
}
func (t *processTree) attach(cmd *exec.Cmd) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pid = cmd.Process.Pid
	return nil
}
func (t *processTree) kill() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pid != 0 {
		_ = syscall.Kill(-t.pid, syscall.SIGKILL)
	}
}
func (t *processTree) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pid != 0 {
		_ = syscall.Kill(-t.pid, syscall.SIGKILL)
		t.pid = 0
	}
}
func secureDirectory(path string) error { return os.Chmod(path, 0700) }
