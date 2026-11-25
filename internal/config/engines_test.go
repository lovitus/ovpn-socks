package config

import "testing"

func TestMixedEnginesPersistWithoutInventedSOCKSPorts(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	vpn, err := s.Save(Profile{Name: "legacy", OVPN: "client\nremote vpn.example 1194", Listen: "127.0.0.1:1080"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"flyssh", "gust"} {
		p, err := s.Save(Profile{Name: name, Engine: name, Arguments: "-L :8080", EngineConfig: "secret config", Listeners: []Listener{{ID: "one", Address: ":8080", Network: "tcp", Scope: "local"}}})
		if err != nil {
			t.Fatal(err)
		}
		if p.Listen != "" {
			t.Fatalf("external engine invented SOCKS port %s", p.Listen)
		}
		p.Listeners[0].Address = "changed"
		got, _ := s.Get(p.ID)
		if got.Listeners[0].Address != ":8080" {
			t.Fatal("saved listener aliases caller")
		}
		list := s.List()
		for i := range list {
			if list[i].ID == p.ID {
				list[i].Listeners[0].Address = "changed"
			}
		}
		got, _ = s.Get(p.ID)
		if got.Listeners[0].Address != ":8080" {
			t.Fatal("list listener aliases store")
		}
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 3 {
		t.Fatal("lost mixed engine profiles")
	}
	got, _ := reopened.Get(vpn.ID)
	if got.EngineName() != "openvpn" || got.Listen != vpn.Listen {
		t.Fatal("legacy profile changed")
	}
}
func TestUnknownEngineRejected(t *testing.T) {
	_, err := validate(Profile{Name: "bad", Engine: "shell", Arguments: "anything"})
	if err == nil {
		t.Fatal("unknown engine accepted")
	}
}
