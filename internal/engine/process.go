package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lovitus/ovpn-socks/internal/engineargs"
)

type prepared struct {
	binary    string
	args      []string
	dir, temp string
}

func prepare(o Options) (_ prepared, err error) {
	p := prepared{}
	defer func() {
		if err != nil {
			p.cleanup()
		}
	}()
	if o.Engine != "flyssh" && o.Engine != "gust" {
		return p, errors.New("unsupported managed engine")
	}
	root := os.Getenv("OVPN_SOCKS_ENGINE_DIR")
	if root == "" {
		exe, e := os.Executable()
		if e != nil {
			return p, errors.New("cannot locate managed engines")
		}
		root = filepath.Join(filepath.Dir(exe), "engines")
	}
	if !filepath.IsAbs(root) {
		return p, errors.New("OVPN_SOCKS_ENGINE_DIR must be absolute")
	}
	p.binary = filepath.Join(root, o.Engine)
	if runtime.GOOS == "windows" {
		p.binary += ".exe"
	}
	st, e := os.Stat(p.binary)
	if e != nil || !st.Mode().IsRegular() {
		return p, errors.New("managed engine binary unavailable; install the instrumented native engine build")
	}
	p.args, e = engineargs.Split(o.Arguments)
	if e != nil {
		return p, e
	}
	if len(p.args) > 0 {
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(p.args[0], "\\", "/"))), ".exe")
		if base == o.Engine || (o.Engine == "gust" && base == "gost") {
			p.args = p.args[1:]
		}
	}
	if o.WorkingDirectory != "" {
		if !filepath.IsAbs(o.WorkingDirectory) {
			return p, errors.New("working directory must be absolute")
		}
		st, e = os.Stat(o.WorkingDirectory)
		if e != nil || !st.IsDir() {
			return p, errors.New("working directory unavailable")
		}
		p.dir = o.WorkingDirectory
	}
	flag, ext := "-F", "ssh"
	if o.Engine == "gust" {
		flag, ext = "-C", "yaml"
		if o.ConfigFormat != "" {
			ext = strings.ToLower(o.ConfigFormat)
		}
		if ext != "yaml" && ext != "json" {
			return p, errors.New("gust config format must be yaml or json")
		}
	} else if o.ConfigFormat != "" && o.ConfigFormat != "ssh" {
		return p, errors.New("flyssh config format must be ssh")
	}
	placeholders, hasFlag := 0, false
	for _, a := range p.args {
		placeholders += strings.Count(a, "{config}")
		if a == flag || strings.HasPrefix(a, flag+"=") || (strings.HasPrefix(a, flag) && len(a) > len(flag)) || a == "--config" || strings.HasPrefix(a, "--config=") {
			hasFlag = true
		}
	}
	if o.ConfigText == "" {
		if placeholders > 0 {
			return p, errors.New("config placeholder requires inline config")
		}
		return p, nil
	}
	if len(o.ConfigText) > 2*1024*1024 {
		return p, errors.New("inline config exceeds 2 MiB")
	}
	if placeholders > 1 || (hasFlag && placeholders == 0) {
		return p, errors.New("ambiguous config: use one {config} placeholder with inline config")
	}
	p.temp, e = os.MkdirTemp("", "ovpn-engine-")
	if e != nil {
		return p, errors.New("cannot create private engine config directory")
	}
	if e = secureDirectory(p.temp); e != nil {
		return p, errors.New("cannot secure private engine config directory")
	}
	name := filepath.Join(p.temp, "config."+ext)
	if e = os.WriteFile(name, []byte(o.ConfigText), 0600); e != nil {
		return p, errors.New("cannot materialize private engine config")
	}
	if placeholders == 0 {
		p.args = append([]string{flag, name}, p.args...)
	} else {
		for i := range p.args {
			p.args[i] = strings.ReplaceAll(p.args[i], "{config}", name)
		}
	}
	return p, nil
}
func (p prepared) cleanup() {
	if p.temp != "" {
		_ = os.RemoveAll(p.temp)
	}
}

type child struct {
	cmd  *exec.Cmd
	tree *processTree
	done chan error
}

func launch(ctx context.Context, p prepared, o Options, kind string, accept func(record)) (*child, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, errors.New("cannot create engine telemetry token")
	}
	c := &child{cmd: exec.Command(p.binary, p.args...), done: make(chan error, 1)}
	c.cmd.Dir = p.dir
	env := make([]string, 0, len(os.Environ())+2)
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if !strings.EqualFold(k, "OVPN_SOCKS_TELEMETRY_TOKEN") && !strings.EqualFold(k, "OVPN_SOCKS_INSPECT") {
			env = append(env, v)
		}
	}
	c.cmd.Env = append(env, "OVPN_SOCKS_TELEMETRY_TOKEN="+hex.EncodeToString(token[:]))
	if kind == "inspect" {
		c.cmd.Env = append(c.cmd.Env, "OVPN_SOCKS_INSPECT=1")
	}
	c.cmd.Stdout = &lineSink{prefix: "OVPN_ENGINE_" + hex.EncodeToString(token[:]) + " ", engine: o.Engine, kind: kind, accept: accept}
	c.cmd.Stderr = io.Discard
	// WaitDelay also bounds inherited pipes if a hostile descendant escapes containment.
	c.cmd.WaitDelay = time.Second
	tree, err := newProcessTree(c.cmd)
	if err != nil {
		return nil, errors.New("cannot create engine process containment")
	}
	c.tree = tree
	if err = c.cmd.Start(); err != nil {
		tree.close()
		return nil, errors.New("cannot start managed engine binary")
	}
	if err = tree.attach(c.cmd); err != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
		tree.close()
		return nil, errors.New("cannot contain managed engine process")
	}
	go func() { err := c.cmd.Wait(); tree.close(); c.done <- err }()
	return c, nil
}
func (c *child) kill() { c.tree.kill(); _ = c.cmd.Process.Kill() }

// Inspect executes the instrumented engine's configuration-only mode, bounded
// to 15 seconds. The engine overlay must honor the protocol's no-I/O contract.
func Inspect(ctx context.Context, o Options) (InspectResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := prepare(o)
	if err != nil {
		return InspectResult{}, err
	}
	defer p.cleanup()
	var result InspectResult
	valid := false
	diagnostic := ""
	c, err := launch(ctx, p, o, "inspect", func(r record) {
		if r.Type == "error" {
			diagnostic = safeDiagnostic(r)
			return
		}
		result.Listeners = r.Listeners
		valid = true
	})
	if err != nil {
		return InspectResult{}, err
	}
	select {
	case err = <-c.done:
	case <-ctx.Done():
		c.kill()
		<-c.done
		return InspectResult{}, errors.New("engine inspection timed out or was canceled")
	}
	if diagnostic != "" {
		return InspectResult{}, errors.New(diagnostic)
	}
	if err != nil {
		return InspectResult{}, errors.New("engine rejected configuration; check native arguments and config syntax")
	}
	if !valid {
		return InspectResult{}, errors.New("engine inspection protocol unavailable; install the instrumented build")
	}
	for i := range result.Listeners {
		result.Listeners[i].State = "configured"
		result.Listeners[i].ActualAddress = ""
		result.Listeners[i].MetricsAvailable = false
	}
	return result, nil
}
