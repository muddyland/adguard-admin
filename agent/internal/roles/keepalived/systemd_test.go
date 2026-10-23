package keepalived

import "os"

func hasSystemdForTest() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}
