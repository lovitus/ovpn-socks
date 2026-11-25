package engineargs

import (
	"reflect"
	"testing"
)

func TestSplitNativeArguments(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{`-L tcp://:8080 -L 'udp://:5353/10.0.0.1:53?ttl=30s&keepalive=true'`, []string{"-L", "tcp://:8080", "-L", "udp://:5353/10.0.0.1:53?ttl=30s&keepalive=true"}},
		{`-C "C:\Users\test user\config.yaml" -L="ltcp://[::1]:9000"`, []string{"-C", `C:\Users\test user\config.yaml`, "-L=ltcp://[::1]:9000"}},
		{"-L tcp://:8080 \\\r\n -L udp://:8080", []string{"-L", "tcp://:8080", "-L", "udp://:8080"}},
		{`--name "" --key '$HOME/$(echo nope)'`, []string{"--name", "", "--key", "$HOME/$(echo nope)"}},
		{`--name one\ two`, []string{"--name", "one two"}},
		{"", nil},
	}
	for _, tc := range cases {
		got, err := Split(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Split(%q)=%q,%v; want %q", tc.input, got, err, tc.want)
		}
	}
}
func TestRejectMalformedOrShellCommands(t *testing.T) {
	for _, input := range []string{`-L "unterminated`, `-L :1234; echo hello`, `-L :1234 | other`, `-L :1234 > out`, `-L :1234 &`, "-L\x00:1234"} {
		if _, err := Split(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
