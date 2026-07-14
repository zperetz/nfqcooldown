package internal

import "testing"

func TestWhitelistIPv4Only(t *testing.T) {
	w, err := NewWhitelist("192.0.2.1,198.51.100.0/24")
	if err != nil {
		t.Fatalf("NewWhitelist returned error: %v", err)
	}
	if !w.Contains("192.0.2.1") {
		t.Fatal("expected exact IPv4 address to match")
	}
	if !w.Contains("198.51.100.42") {
		t.Fatal("expected IPv4 CIDR address to match")
	}
	if w.Contains("2001:db8::1") {
		t.Fatal("IPv6 must not match")
	}
}

func TestWhitelistRejectsInvalidIPv4Address(t *testing.T) {
	_, err := NewWhitelist("192.0.2.999")
	if err == nil || err.Error() != `invalid IPv4 address "192.0.2.999"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWhitelistRejectsInvalidIPv4Network(t *testing.T) {
	_, err := NewWhitelist("192.0.2.0/99")
	if err == nil || err.Error() != `invalid IPv4 network "192.0.2.0/99"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWhitelistRejectsIPv6(t *testing.T) {
	for _, item := range []string{"2001:db8::1", "2001:db8::/32"} {
		_, err := NewWhitelist(item)
		want := `unsupported address family "` + item + `"`
		if err == nil || err.Error() != want {
			t.Fatalf("item %q: got %v, want %q", item, err, want)
		}
	}
}
