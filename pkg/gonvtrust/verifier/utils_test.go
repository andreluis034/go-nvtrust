package verify_test

import (
	"testing"

	verify "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/verifier"
	"github.com/stretchr/testify/assert"
)

func TestFormatVbiosVersion_Ok(t *testing.T) {
	rawData := []byte{
		0x00, 0x5E, 0x00, 0x96, 0x01, 0x00, 0x00, 0x00,
	}

	version := verify.FormatVbiosVersion(rawData)

	assert.Equal(t, "96.00.5e.00.01", version)
}
