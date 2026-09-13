package main

import "testing"

func TestRequireLoopbackAdminAddr(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		allow   string
		wantErr bool
	}{
		{name: "loopback ipv4", addr: "127.0.0.1:47264", wantErr: false},
		{name: "loopback ipv6", addr: "[::1]:47264", wantErr: false},
		{name: "localhost hostname", addr: "localhost:47264", wantErr: false},
		{name: "all interfaces", addr: "0.0.0.0:47264", wantErr: true},
		{name: "specific interface", addr: "10.0.0.5:47264", wantErr: true},
		{name: "missing port", addr: "127.0.0.1", wantErr: true},
		{name: "override env allows non-loopback", addr: "0.0.0.0:47264", allow: "1", wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.allow != "" {
				t.Setenv("DEFENDSEC_ALLOW_NONLOOPBACK_ADMIN", tc.allow)
			}
			err := requireLoopbackAdminAddr(tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for addr %q", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for addr %q: %v", tc.addr, err)
			}
		})
	}
}
