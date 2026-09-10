package alertmeta

import "testing"

func TestStamp_emptyUsesNow(t *testing.T) {
	detected, ingested := Stamp("")
	if detected == "" || ingested == "" {
		t.Fatal("expected non-empty stamps")
	}
	if detected != ingested {
		t.Fatalf("empty detected should equal ingested, got %q vs %q", detected, ingested)
	}
}

func TestStamp_preservesDetected(t *testing.T) {
	detected, ingested := Stamp("2024-01-02T03:04:05Z")
	if detected != "2024-01-02T03:04:05Z" {
		t.Fatalf("detected = %q", detected)
	}
	if ingested == "" {
		t.Fatal("ingested empty")
	}
}

func TestBaseDetailAndRaw(t *testing.T) {
	d := BaseDetail("host-a")
	if d[KeySchemaVersion] != SchemaVersion {
		t.Fatalf("schema = %v", d[KeySchemaVersion])
	}
	if d[KeyHostName] != "host-a" {
		t.Fatalf("host = %v", d[KeyHostName])
	}
	d = WithRaw(d, map[string]any{"x": 1})
	raw, ok := d[KeyRaw].(map[string]any)
	if !ok || raw["x"] != 1 {
		t.Fatalf("raw = %#v", d[KeyRaw])
	}
}
