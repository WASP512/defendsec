package idposture

import "testing"

func TestContainsTermIsWholeWordAndCaseInsensitive(t *testing.T) {
	cases := []struct {
		text, term string
		want       bool
	}{
		{"ACH payment received", "ach", true},
		{"please reach me", "ach", false},
		{"Wire transfer", "wire", true},
		{"wireless", "wire", false},
		{"new invoice via Bill.com today", "bill.com", true},
		{"a purchase  order", "purchase order", false},
		{"Purchase Order 17", "purchase order", true},
		{"", "wire", false},
		{"wire", "", false},
	}
	for _, c := range cases {
		if got := ContainsTerm(c.text, c.term); got != c.want {
			t.Errorf("ContainsTerm(%q, %q) = %v, want %v", c.text, c.term, got, c.want)
		}
	}
}

func TestPluralAndLabels(t *testing.T) {
	for _, c := range []struct {
		n    int
		word string
		want string
	}{{1, "mailbox", "1 mailbox"}, {2, "mailbox", "2 mailboxes"}, {0, "user", "0 users"}, {3, "class", "3 classes"}} {
		if got := Plural(c.n, c.word); got != c.want {
			t.Errorf("Plural(%d, %q) = %q, want %q", c.n, c.word, got, c.want)
		}
	}
	r := &Report{Labels: map[string]string{"mfa": "2-Step Verification"}}
	if r.Label("mfa") != "2-Step Verification" || r.Label("other") != "other" {
		t.Errorf("labels: %q %q", r.Label("mfa"), r.Label("other"))
	}
}
