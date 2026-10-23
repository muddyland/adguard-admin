// Command adguard-admin-agent is the on-host agent for AdGuard Admin.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/dnsprobe"
	"adguard-admin/agent/internal/enroll"
	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/pki"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/roles/adguard"
	"adguard-admin/agent/internal/roles/dnsdist"
	"adguard-admin/agent/internal/roles/ipvsbackend"
	"adguard-admin/agent/internal/roles/keepalived"
	"adguard-admin/agent/internal/server"
	"adguard-admin/agent/internal/services"
)

func usage() {
	fmt.Fprintf(os.Stderr, `adguard-admin-agent %s

Usage:
  adguard-admin-agent version
  adguard-admin-agent enroll --url <control plane> --token <token> [--listen 0.0.0.0:8443] [--address <ip>] [--name <name>]
  adguard-admin-agent serve
  adguard-admin-agent probe-dns <host:port>

Global flags (also AGENT_CONFIG_DIR / AGENT_STATE_DIR):
  --config-dir   default %s
  --state-dir    default %s
`, server.Version, config.DefaultConfigDir, config.DefaultStateDir)
}

func dirsFlags(fs *flag.FlagSet) *config.Dirs {
	d := &config.Dirs{}
	fs.StringVar(&d.Config, "config-dir", envOr("AGENT_CONFIG_DIR", config.DefaultConfigDir), "configuration directory")
	fs.StringVar(&d.State, "state-dir", envOr("AGENT_STATE_DIR", config.DefaultStateDir), "state directory")
	return d
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	switch os.Args[1] {
	case "version", "--version", "-V":
		fmt.Println(server.Version)
	case "probe-dns":
		fs := flag.NewFlagSet("probe-dns", flag.ExitOnError)
		name := fs.String("name", "a.root-servers.net.", "query name")
		timeout := fs.Duration("timeout", 2*time.Second, "timeout")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "probe-dns needs one host:port argument")
			os.Exit(2)
		}
		if err := dnsprobe.Probe(fs.Arg(0), *name, *timeout); err != nil {
			fmt.Fprintln(os.Stderr, "probe failed:", err)
			os.Exit(1)
		}
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		d := dirsFlags(fs)
		o := enroll.Options{Version: server.Version}
		fs.StringVar(&o.URL, "url", "", "control plane base URL")
		fs.StringVar(&o.Token, "token", "", "provisioning token")
		fs.StringVar(&o.Listen, "listen", config.DefaultListen, "address the agent will listen on")
		fs.StringVar(&o.Address, "address", "", "address the control plane will connect to (default: auto)")
		fs.StringVar(&o.Name, "name", "", "agent name (default: hostname)")
		_ = fs.Parse(os.Args[2:])
		resp, err := enroll.Run(context.Background(), *d, o)
		if err != nil {
			fmt.Fprintln(os.Stderr, "enroll failed:", err)
			os.Exit(1)
		}
		fmt.Printf("enrolled as %q (agent id %d); certificate valid until %s\n", resp.Name, resp.AgentID, resp.NotAfter)
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		d := dirsFlags(fs)
		_ = fs.Parse(os.Args[2:])
		if err := serve(*d, logger); err != nil {
			logger.Fatalf("serve: %v", err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func serve(d config.Dirs, logger *log.Logger) error {
	if !config.Exists(d.CertFile()) || !config.Exists(d.KeyFile()) || !config.Exists(d.CAFile()) {
		return config.ErrNotEnrolled
	}
	cfg, err := config.Load(d)
	if err != nil {
		return err
	}
	// Older agent.json files may predate the dnsdist secrets; Save fills them.
	if cfg.DnsdistAPIKey == "" || cfg.DnsdistConsoleKey == "" {
		if err := config.Save(d, cfg); err != nil {
			return err
		}
	}
	holder := &pki.Holder{}
	if err := holder.LoadFiles(d.CertFile(), d.KeyFile()); err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	for _, dir := range []string{d.Desired(), d.Status(), d.Dnsdist(), d.Keepalived()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	host := services.Host{R: execx.Real{}}
	mgr := roles.NewManager(d, logger,
		adguard.New(host),
		dnsdist.New(host, d, cfg.DnsdistAPIKey, cfg.DnsdistConsoleKey),
		keepalived.NewWithDirs(host, d),
		ipvsbackend.New(host),
	)
	if err := mgr.Load(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	mgr.Start(ctx)
	srv := &server.Server{Dirs: d, Cfg: cfg, Host: host, Manager: mgr, Holder: holder, Logger: logger}
	return srv.ListenAndServe(ctx)
}
