package surface

import (
	"os"
	"strconv"
	"strings"
)

// ConfigFromEnv reads the scanner's settings:
//
//	DEFENDSEC_SURFACE_RESOLVERS             comma-separated resolvers for ordinary lookups (default: /etc/resolv.conf)
//	DEFENDSEC_SURFACE_VALIDATING_RESOLVERS  validating resolvers for the DNSSEC check (default: 1.1.1.1, 9.9.9.9)
//	DEFENDSEC_SURFACE_QPS                   DNS queries and connection attempts per second (default 25)
//
// A resolver without a port gets :53.
func ConfigFromEnv() Config {
	cfg := Config{
		Servers:           splitServers(os.Getenv("DEFENDSEC_SURFACE_RESOLVERS")),
		ValidatingServers: splitServers(os.Getenv("DEFENDSEC_SURFACE_VALIDATING_RESOLVERS")),
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("DEFENDSEC_SURFACE_QPS"))); err == nil && n > 0 {
		cfg.QueriesPerSecond = n
	}
	return cfg
}

func splitServers(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !hasPort(s) {
			if strings.Count(s, ":") > 1 {
				s = "[" + s + "]"
			}
			s += ":53"
		}
		out = append(out, s)
	}
	return out
}

// hasPort tells "host:53" and "[::1]:53" from a bare IPv6 address.
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return strings.Contains(s, "]:")
	}
	return strings.Count(s, ":") == 1
}
