module github.com/rbaliyan/config-crypto/gcpkms

go 1.24.2

require (
	cloud.google.com/go/kms v1.21.1
	github.com/rbaliyan/config-crypto v0.0.0
)

require (
	cloud.google.com/go/longrunning v0.6.5 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/rbaliyan/config v0.2.3 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250227231956-55c901821b1e // indirect
	google.golang.org/grpc v1.71.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/rbaliyan/config-crypto => ../
