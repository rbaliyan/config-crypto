module github.com/rbaliyan/config-crypto/azurekv

go 1.25.9

require (
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.4.0
	github.com/rbaliyan/config-crypto v0.2.5
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.21.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/rbaliyan/config v0.6.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

replace github.com/rbaliyan/config-crypto => ../
