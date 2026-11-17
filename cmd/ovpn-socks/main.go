package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	addr := flag.String("listen", "127.0.0.1:2080", "本机管理页面监听地址")
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
		decoder := json.NewDecoder(f)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			return err
		}
		if _, err := ovpnconfig.Parse(p.OVPN); err != nil {
			return err
		}
		saved, err := store.Save(p)
		if err != nil {
			return err
		}
		fmt.Println("已加密导入:", saved.ID, saved.Name, "SOCKS", saved.Listen)
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
	url := server.URL(listener.Addr().String())
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Println("OVPN → SOCKS", version, "(用户态 OpenVPN + gVisor)")
	fmt.Println("数据目录:", *dir)
	fmt.Println("管理页面:", url)
	fmt.Println("请妥善保管上面的本机访问链接。Ctrl+C 停止所有连接。")
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
