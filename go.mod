module github.com/lovitus/ovpn-socks

go 1.26.0

require (
	github.com/sagernet/sing-openvpn v0.0.0
	golang.org/x/crypto v0.48.0
	golang.org/x/net v0.50.0
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20
)

require (
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/sagernet/sing v0.8.12-0.20260702081104-2ded2af32d3d // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/time v0.11.0 // indirect
)

replace github.com/sagernet/sing-openvpn => ./third_party/sing-openvpn
