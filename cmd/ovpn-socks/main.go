package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/lovitus/ovpn-socks/internal/app"
	"github.com/lovitus/ovpn-socks/internal/config"
	"github.com/lovitus/ovpn-socks/internal/engine"
	"github.com/lovitus/ovpn-socks/internal/ovpnconfig"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}
func run() error {
	addr := flag.String("listen", "0.0.0.0:2080", "Web 管理监听地址，例如 0.0.0.0:2080、192.168.1.10:8080、[::]:2080")
	dir := flag.String("data-dir", "", "加密数据目录（默认用户配置目录/ovpn-socks）")
	noBrowser := flag.Bool("no-browser", false, "不自动打开浏览器")
	showVersion := flag.Bool("version", false, "显示版本")
	importPath := flag.String("import", "", "导入配置JSON（含ovpn、username、password等），仅写本机加密存储")
	flag.Parse()
	if *showVersion {
		fmt.Println("ovpn-socks", version, runtime.GOOS+"/"+runtime.GOARCH)
		return nil
	}
	if *dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		*dir = filepath.Join(base, "ovpn-socks")
	}
	store, err := config.Open(*dir)
	if err != nil {
		return err
	}
	if *importPath != "" {
		f := os.Stdin
		if *importPath != "-" {
			var err error
			f, err = os.Open(*importPath)
			if err != nil {
				return err
			}
			defer f.Close()
		}
		var p config.Profile
		limited := &io.LimitedReader{R: f, N: 8*1024*1024 + 1}
		decoder := json.NewDecoder(limited)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			return err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return fmt.Errorf("导入文件必须仅包含一个 JSON 配置对象")
		}
		if limited.N <= 0 {
			return fmt.Errorf("导入文件超过 8 MiB 上限")
		}
		p.Listeners = nil
		if p.EngineName() == "openvpn" {
			if _, err := ovpnconfig.Parse(p.OVPN); err != nil {
				return err
			}
		} else {
			parsed, err := engine.Inspect(context.Background(), engine.Options{Engine: p.EngineName(), Arguments: p.Arguments, ConfigText: p.EngineConfig, ConfigFormat: p.ConfigFormat, WorkingDirectory: p.WorkingDirectory})
			if err != nil {
				return err
			}
			for _, l := range parsed.Listeners {
				p.Listeners = append(p.Listeners, config.Listener{ID: l.ID, Network: l.Network, Address: l.Address, Scope: l.Scope, Kind: l.Kind})
			}
		}
		saved, err := store.Save(p)
		if err != nil {
			return err
		}
		fmt.Println("已加密导入:", saved.ID, saved.Name, "引擎", saved.EngineName(), saved.Listen)
		return nil
	}
	if err := app.ValidateListen(*addr); err != nil {
		return err
	}
	server, err := app.New(store, "")
	if err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	browserHost, browserPort, _ := net.SplitHostPort(listener.Addr().String())
	if ip := net.ParseIP(browserHost); ip == nil || ip.IsUnspecified() {
		browserHost = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(browserHost, browserPort) + "/"
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Println("OVPN → SOCKS", version, "(OpenVPN + gVisor / FlySSH / gust)")
	fmt.Println("数据目录:", *dir)
	fmt.Println("管理页面:", url)
	fmt.Println("Web 监听:", listener.Addr().String(), "（远程访问请使用本机对应接口 IP）")
	fmt.Println("初始管理账号: admin / admin；可在 Web 页面修改。已有账户设置会保留。")
	fmt.Println("Ctrl+C 停止所有连接。")
	for _, err := range server.AutoStart() {
		fmt.Fprintln(os.Stderr, "自动连接:", err)
	}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	if !*noBrowser {
		openBrowser(url)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	case err := <-done:
		if err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}
func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		c = exec.Command("open", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	if err := c.Start(); err == nil {
		go func() { _ = c.Wait() }()
	}
}
