package defendsecv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// The source_package/source_version/distro fields are optional: a message that
// carries them must round-trip, and one that does not (an agent older than the
// distro-aware matcher) must decode with them empty and the rest intact.

func TestInventoryReportRoundTripWithSourceFields(t *testing.T) {
	in := &InventoryReport{
		Distro:         "ubuntu",
		DistroRelease:  "22.04",
		PackageManager: "dpkg",
		Software: []*SoftwareItem{
			{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.11", SourcePackage: "openssh"},
			{Name: "libc6", Version: "2.35-0ubuntu3.8+b1", SourcePackage: "glibc", SourceVersion: "2.35-0ubuntu3.8"},
		},
	}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &InventoryReport{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("round trip changed the message:\n in: %v\nout: %v", in, out)
	}
	if got := out.GetSoftware()[1]; got.GetSourcePackage() != "glibc" || got.GetSourceVersion() != "2.35-0ubuntu3.8" {
		t.Fatalf("source fields lost: %v", got)
	}
	if out.GetDistro() != "ubuntu" || out.GetDistroRelease() != "22.04" || out.GetPackageManager() != "dpkg" {
		t.Fatalf("distro fields lost: %v", out)
	}
}

func TestInventoryReportRoundTripWithoutSourceFields(t *testing.T) {
	in := &InventoryReport{
		Software: []*SoftwareItem{{Name: "bash", Version: "5.1-6ubuntu1"}},
	}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &InventoryReport{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("round trip changed the message: %v vs %v", in, out)
	}
	it := out.GetSoftware()[0]
	if it.GetName() != "bash" || it.GetVersion() != "5.1-6ubuntu1" {
		t.Fatalf("name/version lost: %v", it)
	}
	if it.GetSourcePackage() != "" || it.GetSourceVersion() != "" {
		t.Fatalf("absent source fields decoded non-empty: %v", it)
	}
	if out.GetDistro() != "" || out.GetDistroRelease() != "" || out.GetPackageManager() != "" {
		t.Fatalf("absent distro fields decoded non-empty: %v", out)
	}
}

// An old agent's bytes: the same SoftwareItem encoded with only fields 1 and 2
// by hand, so the test does not depend on the generated struct having the new
// fields at all.
func TestSoftwareItemDecodesOldWireFormat(t *testing.T) {
	// field 1 (name) "curl", field 2 (version) "7.81.0"
	wire := []byte{0x0a, 0x04, 'c', 'u', 'r', 'l', 0x12, 0x06, '7', '.', '8', '1', '.', '0'}
	var it SoftwareItem
	if err := proto.Unmarshal(wire, &it); err != nil {
		t.Fatal(err)
	}
	if it.GetName() != "curl" || it.GetVersion() != "7.81.0" || it.GetSourcePackage() != "" || it.GetSourceVersion() != "" {
		t.Fatalf("old wire format decoded wrong: %v", &it)
	}
}
