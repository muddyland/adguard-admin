package execx

import (
	"context"
	"strings"
	"testing"
)

const dockerRunStderr = `Unable to find image 'adguard/adguardhome:latest' locally
latest: Pulling from adguard/adguardhome
e6f31ffc071e: Pulling fs layer
e6f31ffc071e: Pull complete
Digest: sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0
Status: Downloaded newer image for adguard/adguardhome:latest
docker: Error response from daemon: failed to set up container networking: failed to bind host port 127.0.0.1:3000/tcp: address already in use

Run 'docker run --help' for more information
`

func TestLastLineSkipsPullProgressAndHelpHint(t *testing.T) {
	got := LastLine(dockerRunStderr)
	want := "docker: Error response from daemon: failed to set up container networking: failed to bind host port 127.0.0.1:3000/tcp: address already in use"
	if got != want {
		t.Fatalf("LastLine = %q", got)
	}
	if LastLine("\n  \n") != "" {
		t.Fatal("blank stderr should give an empty line")
	}
	if LastLine("only line") != "only line" {
		t.Fatal("single line should be returned as is")
	}
}

func TestRealErrorCarriesOnlyTheLastLine(t *testing.T) {
	_, stderr, err := Real{}.Run(context.Background(), "sh", "-c", "echo first >&2; echo second >&2; exit 3")
	if err == nil {
		t.Fatal("expected an error")
	}
	// The command line itself mentions "first"; what must not appear is the
	// earlier stderr line ahead of the last one.
	if !strings.HasSuffix(err.Error(), "exit status 3: second") {
		t.Fatalf("error = %q", err)
	}
	if strings.Contains(err.Error(), "first\nsecond") {
		t.Fatalf("error should not embed earlier lines: %q", err)
	}
	if !strings.Contains(string(stderr), "first") {
		t.Fatal("the raw stderr must still be returned whole")
	}
}
