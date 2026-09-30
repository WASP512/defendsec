package agentcmd

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

func runCmd(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", strings.Join(argv[:min(len(argv), 4)], " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func lookupHost(h string) ([]string, error) {
	return net.DefaultResolver.LookupHost(context.Background(), h)
}
