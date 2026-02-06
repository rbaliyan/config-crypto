module github.com/rbaliyan/config-crypto/awskms

go 1.24.2

require (
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.5
	github.com/rbaliyan/config-crypto v0.0.0
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/rbaliyan/config v0.2.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/rbaliyan/config-crypto => ../
