// Package sysinfo reads host facts from /proc and statfs.
package sysinfo

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Load returns the 1/5/15 minute load averages.
func Load() []float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(raw))
	if len(f) < 3 {
		return nil
	}
	out := make([]float64, 0, 3)
	for _, s := range f[:3] {
		v, _ := strconv.ParseFloat(s, 64)
		out = append(out, v)
	}
	return out
}

// Mem returns total and available memory in bytes.
func Mem() (total, available uint64) {
	fh, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	return total, available
}

// Disk is one filesystem's size.
type Disk struct {
	Path       string `json:"path"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// DiskUsage reports a path's filesystem size, or ok=false when it cannot.
func DiskUsage(path string) (Disk, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, false
	}
	bs := uint64(st.Bsize)
	return Disk{Path: path, TotalBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs}, true
}

// Uptime returns seconds since boot.
func Uptime() int64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

// Kernel returns the kernel release string.
func Kernel() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// Hostname returns the host name or "unknown".
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// OS and Arch are the Go runtime's view, which matches the download names.
func OS() string   { return runtime.GOOS }
func Arch() string { return runtime.GOARCH }

// HasSystemd reports whether this host is booted with systemd.
func HasSystemd() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}
