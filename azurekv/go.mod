module github.com/rbaliyan/config-crypto/azurekv

go 1.24.2

require (
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.4.0
	github.com/rbaliyan/config-crypto v0.0.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.18.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/rbaliyan/config v0.2.3 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/rbaliyan/config-crypto => ../
