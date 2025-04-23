module github.com/confidentsecurity/go-nvtrust

go 1.23.0

toolchain go1.23.1

require (
	github.com/NVIDIA/go-nvml v0.12.4-0
	github.com/beevik/etree v1.5.0
	github.com/russellhaering/goxmldsig v1.5.0
	golang.org/x/crypto v0.37.0
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.10.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/NVIDIA/go-nvml => github.com/confidentsecurity/go-nvml v0.0.0-20250102214226-9a52cebf0382
