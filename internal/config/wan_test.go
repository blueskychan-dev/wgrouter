package config

import (
	"os"
	"path/filepath"
	"testing"
)

// withRouteFile points the detector at a fixture for the duration of a test.
func withRouteFile(t *testing.T, contents string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	orig := procNetRoute
	procNetRoute = path
	t.Cleanup(func() { procNetRoute = orig })
}

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestDetectWANInterface(t *testing.T) {
	tests := []struct {
		name    string
		routes  string
		want    string
		wantErr bool
	}{
		{
			name: "single default route",
			routes: routeHeader +
				"enp0s6\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"enp0s6\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			want: "enp0s6",
		},
		{
			name: "lowest metric wins",
			routes: routeHeader +
				"wwan0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "ignores non-default routes",
			routes: routeHeader +
				"wg0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
				"eth0\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "a zero destination with a non-zero mask is not a default route",
			routes: routeHeader +
				"eth0\t00000000\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
			wantErr: true,
		},
		{
			name:    "no routes at all",
			routes:  routeHeader,
			wantErr: true,
		},
		{
			name:    "empty file",
			routes:  "",
			wantErr: true,
		},
		{
			name: "short lines are skipped rather than panicking",
			routes: routeHeader +
				"garbage\n" +
				"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRouteFile(t, tt.routes)
			got, err := DetectWANInterface()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DetectWANInterface() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DetectWANInterface: %v", err)
			}
			if got != tt.want {
				t.Errorf("DetectWANInterface() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectWANInterfaceMissingFile(t *testing.T) {
	orig := procNetRoute
	procNetRoute = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { procNetRoute = orig })

	if _, err := DetectWANInterface(); err == nil {
		t.Error("DetectWANInterface with a missing file succeeded, want an error")
	}
}

// An explicit -wan-interface must not be overwritten by detection.
func TestExplicitWANInterfaceWins(t *testing.T) {
	withRouteFile(t, routeHeader+"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")

	cfg, err := Load(baseArgs("-wan-interface", "ens5"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WANInterface != "ens5" {
		t.Errorf("WANInterface = %q, want the explicit value ens5", cfg.WANInterface)
	}
}

func TestWANInterfaceIsDetectedWhenUnset(t *testing.T) {
	withRouteFile(t, routeHeader+"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")

	cfg, err := Load(baseArgs())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WANInterface != "eth0" {
		t.Errorf("WANInterface = %q, want the detected eth0", cfg.WANInterface)
	}
}
