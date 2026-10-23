// Package server is the agent's mTLS HTTP API.
package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/pki"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/roles/adguard"
	"adguard-admin/agent/internal/roles/dnsdist"
	"adguard-admin/agent/internal/roles/keepalived"
	"adguard-admin/agent/internal/selfupdate"
	"adguard-admin/agent/internal/services"
	"adguard-admin/agent/internal/sysinfo"
)

// Version is set by the build (ldflags) and read by /v1/info.
var Version = "0.1.0-dev"

// Server holds everything the handlers need.
type Server struct {
	Dirs    config.Dirs
	Cfg     *config.Agent
	Host    services.Host
	Manager *roles.Manager
	Holder  *pki.Holder
	Logger  *log.Logger
	// Updater swaps the binary on POST /v1/self-update; nil builds a default.
	Updater *selfupdate.Updater

	renewMu    sync.Mutex
	pendingKey *ecdsa.PrivateKey
}

// Handler builds the routed handler, with the client-certificate policy in front.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("PUT /v1/adguard", s.putRole("adguard"))
	mux.HandleFunc("GET /v1/adguard", s.getRole("adguard"))
	mux.HandleFunc("POST /v1/adguard/update", s.adguardUpdate)
	mux.HandleFunc("POST /v1/adguard/reset", s.adguardReset)
	mux.HandleFunc("POST /v1/self-update", s.selfUpdate)
	mux.HandleFunc("/v1/adguard/api/", s.adguardProxy)
	mux.HandleFunc("PUT /v1/dnsdist", s.putRole("dnsdist"))
	mux.HandleFunc("GET /v1/dnsdist", s.getRole("dnsdist"))
	mux.HandleFunc("POST /v1/dnsdist/backends/{name}/drain", s.drain(true))
	mux.HandleFunc("POST /v1/dnsdist/backends/{name}/undrain", s.drain(false))
	mux.HandleFunc("PUT /v1/keepalived", s.putRole("keepalived"))
	mux.HandleFunc("GET /v1/keepalived", s.getRole("keepalived"))
	mux.HandleFunc("POST /v1/keepalived/backends/{name}/drain", s.ipvsDrain(true))
	mux.HandleFunc("POST /v1/keepalived/backends/{name}/undrain", s.ipvsDrain(false))
	mux.HandleFunc("PUT /v1/ipvs-backend", s.putRole("ipvs_backend"))
	mux.HandleFunc("GET /v1/ipvs-backend", s.getRole("ipvs_backend"))
	mux.HandleFunc("POST /v1/services/{name}/restart", s.restart)
	mux.HandleFunc("GET /v1/logs", s.logs)
	mux.HandleFunc("POST /v1/cert/renew", s.certRenew)
	mux.HandleFunc("PUT /v1/cert", s.certPut)
	return pki.RequireControlPlane(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rolesOn := []string{}
	hashes := map[string]any{}
	for _, name := range s.Manager.Names() {
		h := s.Manager.DesiredHash(name)
		if h == nil {
			hashes[name] = nil
			continue
		}
		hashes[name] = *h
		if enabled(s.Manager.Spec(name)) {
			rolesOn = append(rolesOn, name)
		}
	}
	var notAfter any
	if t := s.Holder.NotAfter(); !t.IsZero() {
		notAfter = t.UTC().Format(time.RFC3339)
	}
	writeJSON(w, 200, map[string]any{
		"agent_version": Version, "agent_id": s.Cfg.AgentID, "name": s.Cfg.Name,
		"hostname": sysinfo.Hostname(), "os": sysinfo.OS(), "arch": sysinfo.Arch(),
		"kernel": sysinfo.Kernel(), "uptime_s": sysinfo.Uptime(),
		"docker": s.Host.HasDocker(ctx), "systemd": s.Host.HasSystemd(),
		"package_manager": s.Host.PackageManager(),
		"listen":          s.Cfg.Listen, "cert_not_after": notAfter,
		"roles": rolesOn, "desired_hashes": hashes,
	})
}

func enabled(spec any) bool {
	switch t := spec.(type) {
	case *adguard.Spec:
		return t != nil && t.Enabled
	case *dnsdist.Spec:
		return t != nil && t.Enabled
	case interface{ IsEnabled() bool }:
		return t.IsEnabled()
	}
	// keepalived and anything else: reflect through JSON.
	raw, err := json.Marshal(spec)
	if err != nil || spec == nil {
		return false
	}
	var v struct {
		Enabled *bool `json:"enabled"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Enabled != nil && *v.Enabled
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	total, avail := sysinfo.Mem()
	disks := []any{}
	if d, ok := sysinfo.DiskUsage("/"); ok {
		disks = append(disks, d)
	}
	if s.Host.HasDocker(ctx) {
		if root := s.Host.DockerRootDir(ctx); root != "" && root != "/" {
			if d, ok := sysinfo.DiskUsage(root); ok {
				disks = append(disks, d)
			}
		}
	}
	svcs := map[string]any{}
	for _, name := range []string{"adguard", "dnsdist", "keepalived"} {
		st := s.Host.Probe(ctx, name)
		if c := s.Manager.Common(name); c.Version != "" && st.Present {
			v := c.Version
			st.Version = &v
		}
		svcs[name] = st
	}
	writeJSON(w, 200, map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339),
		"load":  sysinfo.Load(),
		"mem":   map[string]uint64{"total_bytes": total, "available_bytes": avail},
		"disks": disks, "services": svcs,
	})
}

func (s *Server) putRole(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		hash, err := s.Manager.Put(name, raw)
		if err != nil {
			writeErr(w, 422, err)
			return
		}
		writeJSON(w, 202, map[string]any{"accepted": true, "hash": hash})
	}
}

func (s *Server) getRole(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := s.Manager.Status(r.Context(), name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, body)
	}
}

func (s *Server) adguardRole() (*adguard.Role, *adguard.Spec) {
	role, _ := s.Manager.Role("adguard")
	ar, _ := role.(*adguard.Role)
	spec, _ := s.Manager.Spec("adguard").(*adguard.Spec)
	return ar, spec
}

func (s *Server) adguardUpdate(w http.ResponseWriter, r *http.Request) {
	ar, spec := s.adguardRole()
	if ar == nil || spec == nil {
		writeErr(w, 409, errors.New("adguard is not managed on this host"))
		return
	}
	hash := ""
	if h := s.Manager.DesiredHash("adguard"); h != nil {
		hash = *h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	started, msg, err := ar.Update(ctx, spec, hash)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"started": started, "message": msg})
}

// adguardReset wipes the install and lets the converge loop rebuild it from
// the spec, so the first-run wizard runs again with the control plane's
// credentials. Refused while a converge holds the role, rather than queued
// behind it: the operator asked for a wipe now, not in ten minutes.
func (s *Server) adguardReset(w http.ResponseWriter, r *http.Request) {
	ar, spec := s.adguardRole()
	if ar == nil || spec == nil {
		writeErr(w, 409, errors.New("adguard is not managed on this host"))
		return
	}
	unlock, ok := s.Manager.TryLockConverge("adguard")
	if !ok {
		writeErr(w, 409, errors.New("a converge is in flight for adguard; retry shortly"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := ar.Reset(ctx, spec)
	unlock()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.Logger.Printf("adguard: install wiped on request; converging from scratch")
	s.Manager.ResetApplied("adguard")
	s.Manager.Wake("adguard")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// selfUpdate replaces the agent binary and, under systemd, exits one second
// after replying so the service manager starts the new one.
func (s *Server) selfUpdate(w http.ResponseWriter, r *http.Request) {
	var req selfupdate.Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if s.Updater == nil {
		s.Updater = &selfupdate.Updater{Version: Version, Logger: s.Logger}
	}
	resp, uerr := s.Updater.Apply(r.Context(), req)
	if uerr != nil {
		writeErr(w, uerr.Status, uerr.Err)
		return
	}
	writeJSON(w, 200, resp)
	if resp.Restarting {
		s.Updater.ScheduleRestart()
	}
}

var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade"}

func (s *Server) adguardProxy(w http.ResponseWriter, r *http.Request) {
	_, spec := s.adguardRole()
	if spec == nil || s.Manager.Common("adguard").State != "ready" {
		writeErr(w, 503, errors.New("adguard is not ready"))
		return
	}
	target, _ := url.Parse(spec.LocalBase())
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/v1/adguard/api"), "/")
			req.URL.RawPath = ""
			req.Host = target.Host
			for _, h := range hopByHop {
				req.Header.Del(h)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeErr(w, 502, fmt.Errorf("adguard did not answer: %w", err))
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) drain(drain bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := s.Manager.Role("dnsdist")
		dr, _ := role.(*dnsdist.Role)
		if dr == nil {
			writeErr(w, 500, errors.New("dnsdist role missing"))
			return
		}
		name := r.PathValue("name")
		err := dr.SetDrained(r.Context(), s.Manager.Spec("dnsdist"), name, drain)
		if err != nil {
			status := 500
			if strings.Contains(err.Error(), "no backend named") {
				status = 404
			}
			writeErr(w, status, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func (s *Server) ipvsDrain(drain bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := s.Manager.Role("keepalived")
		kr, _ := role.(*keepalived.Role)
		if kr == nil {
			writeErr(w, 500, errors.New("keepalived role missing"))
			return
		}
		name := r.PathValue("name")
		err := kr.SetDrained(r.Context(), s.Manager.Spec("keepalived"), name, drain)
		if err != nil {
			status := 500
			if strings.Contains(err.Error(), "no backend named") {
				status = 404
			} else if strings.Contains(err.Error(), "not managed") {
				status = 409
			}
			writeErr(w, status, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := services.Table[name]; !ok || name == "agent" {
		writeErr(w, 404, fmt.Errorf("unknown service %q", name))
		return
	}
	if err := s.Host.Restart(r.Context(), name); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": name + " restarted"})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("service")
	if _, ok := services.Table[name]; !ok {
		writeErr(w, 400, errors.New("service must be adguard, dnsdist, keepalived or agent"))
		return
	}
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	out, err := s.Host.Logs(r.Context(), name, lines)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"lines": out})
}

func (s *Server) certRenew(w http.ResponseWriter, r *http.Request) {
	key, err := pki.GenerateKey()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	csr, err := pki.CSR(key, s.Cfg.Name, s.Cfg.Address)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.renewMu.Lock()
	s.pendingKey = key
	s.renewMu.Unlock()
	writeJSON(w, 200, map[string]string{"csr_pem": string(csr)})
}

func (s *Server) certPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, 400, err)
		return
	}
	s.renewMu.Lock()
	key := s.pendingKey
	s.renewMu.Unlock()
	if key == nil {
		writeErr(w, 409, errors.New("no certificate renewal is pending; call POST /v1/cert/renew first"))
		return
	}
	cert, err := pki.ParseCert([]byte(body.CertPEM))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if !pki.PublicKeyMatches(cert, key) {
		writeErr(w, 400, errors.New("certificate does not match the pending key"))
		return
	}
	keyPEM, err := pki.EncodeKey(key)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if err := s.Holder.Load([]byte(body.CertPEM), keyPEM); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := config.WriteFileAtomic(s.Dirs.KeyFile(), keyPEM, 0o600); err != nil {
		writeErr(w, 500, err)
		return
	}
	if err := config.WriteFileAtomic(s.Dirs.CertFile(), []byte(body.CertPEM), 0o644); err != nil {
		writeErr(w, 500, err)
		return
	}
	if body.CAPEM != "" {
		_ = config.WriteFileAtomic(s.Dirs.CAFile(), []byte(body.CAPEM), 0o644)
	}
	s.renewMu.Lock()
	s.pendingKey = nil
	s.renewMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "not_after": cert.NotAfter.UTC().Format(time.RFC3339)})
}

// ListenAndServe runs the mTLS server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	caPEM, err := os.ReadFile(s.Dirs.CAFile())
	if err != nil {
		return err
	}
	pool, err := pki.Pool(caPEM)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		TLSConfig:         pki.ServerTLSConfig(s.Holder, pool),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          s.Logger,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.Logger.Printf("listening on %s (mTLS)", s.Cfg.Listen)
	err = srv.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
