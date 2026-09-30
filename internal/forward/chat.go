package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ChatDestination posts alerts to Slack or Microsoft Teams incoming webhooks
// (roadmap 5.6). Only alerts at or above a minimum severity are posted —
// events never are: a chat channel that receives every process execution is
// a channel everyone mutes, and then the alert that mattered is muted too.
type ChatDestination struct {
	kind   string // slack or teams
	url    string
	min    int
	client *http.Client
}

// maxChatLines bounds one post; the rest is summarised as a count.
const maxChatLines = 10

// NewChat creates a Slack or Teams destination. opts is "min=high" style.
func NewChat(kind, raw, opts string) (*ChatDestination, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%s webhook %q must be an https URL", kind, raw)
	}
	d := &ChatDestination{kind: kind, url: raw, min: severityRank("high"), client: &http.Client{Timeout: 15 * time.Second}}
	for _, opt := range strings.Split(opts, "&") {
		if opt == "" {
			continue
		}
		k, v, _ := strings.Cut(opt, "=")
		switch k {
		case "min":
			r := severityRank(v)
			if r < 0 {
				return nil, fmt.Errorf("%s min=%q is not low, medium, high or critical", kind, v)
			}
			d.min = r
		default:
			return nil, fmt.Errorf("%s option %q is not recognised (min=)", kind, k)
		}
	}
	return d, nil
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return -1
	}
}

// Name identifies it without the webhook secret, which is in the path.
func (d *ChatDestination) Name() string {
	if u, err := url.Parse(d.url); err == nil {
		return d.kind + ":" + u.Host
	}
	return d.kind
}

// Close is a no-op.
func (d *ChatDestination) Close() error { return nil }

func (d *ChatDestination) selected(records []Record) []Record {
	var out []Record
	for _, r := range records {
		if r.Kind == "alert" && severityRank(r.Severity) >= d.min {
			out = append(out, r)
		}
	}
	return out
}

func chatLine(r Record) string {
	host := r.Hostname
	if host == "" {
		host = r.DeviceID
	}
	return fmt.Sprintf("[%s] %s — %s", strings.ToUpper(r.Severity), host, r.Summary)
}

// Payload builds the webhook body, or nil when nothing qualifies.
func (d *ChatDestination) Payload(records []Record) any {
	sel := d.selected(records)
	if len(sel) == 0 {
		return nil
	}
	lines := make([]string, 0, maxChatLines+1)
	for i, r := range sel {
		if i == maxChatLines {
			lines = append(lines, fmt.Sprintf("…and %d more. See the DefendSec console.", len(sel)-maxChatLines))
			break
		}
		lines = append(lines, chatLine(r))
	}
	title := fmt.Sprintf("DefendSec: %d new alert%s", len(sel), map[bool]string{true: "", false: "s"}[len(sel) == 1])
	if d.kind == "slack" {
		// Plain text with mrkdwn off: alert summaries contain paths and
		// command lines, and Slack formatting would mangle them.
		return map[string]any{"text": title + "\n" + strings.Join(lines, "\n"), "mrkdwn": false}
	}
	// Teams Workflows webhooks take an Adaptive Card in a message envelope.
	body := []map[string]any{{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true}}
	for _, l := range lines {
		body = append(body, map[string]any{"type": "TextBlock", "text": l, "wrap": true})
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard", "version": "1.4", "body": body,
			},
		}},
	}
}

// Send posts qualifying alerts; a batch with none is not sent.
func (d *ChatDestination) Send(ctx context.Context, records []Record) error {
	payload := d.Payload(records)
	if payload == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s webhook returned %s", d.kind, res.Status)
	}
	return nil
}
