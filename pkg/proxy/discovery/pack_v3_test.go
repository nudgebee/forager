package discovery

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func loadPackV3(t *testing.T) *Pack {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/content-packs/linux-inventory-v3.yaml")
	if err != nil {
		t.Fatalf("reading v3 pack: %v", err)
	}
	pack, err := ParseUnverified(raw)
	if err != nil {
		t.Fatalf("v3 pack does not load: %v", err)
	}
	return pack
}

func TestPackV3OnlyAddsHostFacts(t *testing.T) {
	v2, v3 := loadExamplePack(t), loadPackV3(t)

	if v3.Version != 3 {
		t.Fatalf("version = %d, want 3", v3.Version)
	}
	added := []string{"cpu-arch", "cpu-flags", "processes"}
	if len(v3.Collectors) != len(v2.Collectors)+len(added) {
		t.Fatalf("v3 has %d collectors, want %d", len(v3.Collectors), len(v2.Collectors)+len(added))
	}
	for i, want := range v2.Collectors {
		got := v3.Collectors[i]
		if got.ID != want.ID || got.When != want.When || got.Cmd != want.Cmd {
			t.Errorf("collector %q differs from v2", want.ID)
		}
	}
	for i, id := range added {
		got := v3.Collectors[len(v2.Collectors)+i]
		if got.ID != id || got.When != "" {
			t.Errorf("added collector %d = %q (when %q), want unguarded %q", i, got.ID, got.When, id)
		}
	}
}

// runProcessesCollector runs the pack's real command against a stand-in ps.
func runProcessesCollector(t *testing.T, fakePS string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the command reads /proc")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ps"), []byte("#!/bin/sh\n"+fakePS), 0o700); err != nil {
		t.Fatalf("writing fake ps: %v", err)
	}
	cmd := exec.Command("sh", "-c", collectorCmd(t, loadPackV3(t), "processes"))
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running processes collector: %v", err)
	}
	// Present only on test hosts that mount /proc with hidepid.
	return strings.TrimPrefix(string(out), "#restricted\n")
}

func TestPackV3ProcessesDropsEverythingButAllowedFlags(t *testing.T) {
	got := runProcessesCollector(t, `cat <<'OUT'
java            /usr/bin/java -Dpassword=hunter2 -XX:-UseBASE64Intrinsics -XX:+UseG1GC -XX:UseAVX=2 -XX:MaxHeapSize=4g -XX:MaxRAMPercentage=70.0 -jar app.jar --token=abc123
java            java -XX:OnError=curl_http://u:s3cret@host -XX:HeapDumpPath=/home/alice/dump -XX:Flags=/etc/jvm
mysql           mysql -ps3cret
OUT
`)
	want := "java -XX:-UseBASE64Intrinsics -XX:+UseG1GC -XX:UseAVX=2 -XX:MaxHeapSize=4g -XX:MaxRAMPercentage=70.0\njava\nmysql\n"
	if got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestPackV3ProcessesMarksMissingPS(t *testing.T) {
	if got := runProcessesCollector(t, "exit 127\n"); got != "#unavailable\n" {
		t.Errorf("output = %q, want the #unavailable marker", got)
	}
}

func TestPackV3ProcessesFallsBackWhenPSRejectsFlags(t *testing.T) {
	got := runProcessesCollector(t, `[ "$1" = "-o" ] || exit 1
printf 'COMMAND          COMMAND\njava             java -XX:UseAVX=2\n'
`)
	if got != "java -XX:UseAVX=2\n" {
		t.Errorf("output = %q, want the header dropped and the flag kept", got)
	}
}

func TestPackV3ProcessesMarksTruncation(t *testing.T) {
	got := runProcessesCollector(t, `i=0; while [ $i -lt 2001 ]; do echo 'sleep sleep 1'; i=$((i+1)); done
`)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2001 || lines[2000] != "#truncated" {
		t.Errorf("got %d lines ending %q, want 2000 and #truncated", len(lines), lines[len(lines)-1])
	}
}
