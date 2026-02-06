module github.com/rbaliyan/config-crypto/awskms

go 1.24.2

require (
	github.com/aws/aws-sdk-go-v2/service/kms v1.38.3
	github.com/rbaliyan/config-crypto v0.0.0
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/rbaliyan/config v0.2.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/rbaliyan/config-crypto => ../
