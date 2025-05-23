package attestation_test

import (
	_ "embed"
	"encoding/hex"
	"testing"

	testdata "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/mocks"
	attestation "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/verifier/attestation"
	"github.com/stretchr/testify/assert"
)

const SPDM_MEASUREMENTS_REQUEST_SIZE = 37

func TestParseSpdmMeasurementRequestMessage(t *testing.T) {

	expectedNonce := [32]byte{
		0x4C, 0xFF, 0x7F, 0x53, 0x80, 0xEA, 0xD8, 0xFA, 0xD8, 0xEC, 0x2C, 0x53, 0x1C, 0x11, 0x0A, 0xCA,
		0x43, 0x02, 0xA8, 0x8F, 0x60, 0x37, 0x92, 0x80, 0x1A, 0x8C, 0xA2, 0x9E, 0xE1, 0x51, 0xAF, 0x2E,
	}

	request, err := hex.DecodeString(string(testdata.AttestationReportData))

	assert.NoError(t, err)

	req, err := attestation.ParseSpdmMeasurementRequestMessage(request)

	assert.NoError(t, err)

	assert.Equal(t, uint8(0x11), req.SpdmVersion)
	assert.Equal(t, uint8(0xE0), req.RequestResponseCode)
	assert.Equal(t, uint8(0x01), req.Param1)
	assert.Equal(t, uint8(0xFF), req.Param2)
	assert.Equal(t, expectedNonce, req.Nonce)
	assert.Equal(t, uint8(0x00), req.SlotIDParam)
}

func TestParseSpdmMeasurementResponseMessage(t *testing.T) {

	expectedNonce := [...]byte{
		0x10, 0x20, 0xEC, 0xB8, 0xF6, 0x4D, 0xCF, 0xD5, 0x0D, 0xAB, 0xB7, 0x60, 0xFC, 0x6A, 0x24, 0x21,
		0x0B, 0xA7, 0x7D, 0x9F, 0x43, 0xA3, 0xA4, 0xDB, 0x17, 0x0A, 0x1F, 0x56, 0x02, 0x83, 0x56, 0x6F,
	}

	expectedSignature := [...]byte{
		0xF2, 0x3C, 0x38, 0x89, 0xD1, 0xEC, 0xAC, 0x1E, 0x08, 0x2B, 0x0F, 0x59, 0xF8, 0xB4, 0x98, 0xAF,
		0x30, 0x9E, 0x22, 0x82, 0x0B, 0x72, 0xDB, 0xCE, 0xE7, 0xA1, 0x8C, 0x2D, 0x86, 0x06, 0xFB, 0x46,
		0x28, 0x73, 0xC1, 0x6C, 0x57, 0x69, 0x8F, 0x0C, 0xF3, 0x0F, 0x1B, 0x93, 0x60, 0xFF, 0x51, 0x3C,
		0x76, 0x9F, 0x20, 0x50, 0x76, 0x21, 0x67, 0x83, 0x85, 0x38, 0x2A, 0x19, 0xB6, 0x78, 0x4F, 0x74,
		0x5C, 0x01, 0x94, 0x41, 0xB6, 0xE9, 0x6B, 0x0A, 0xAA, 0xB5, 0x39, 0x7D, 0x88, 0x26, 0xC2, 0x7D,
		0x99, 0x71, 0xF8, 0xE9, 0x53, 0xB3, 0xE7, 0x88, 0xB3, 0x58, 0x2B, 0x1C, 0x96, 0xC3, 0x8B, 0x80,
	}

	response, err := hex.DecodeString(string(testdata.AttestationReportData))

	assert.NoError(t, err)
	assert.Greater(t, len(response), 37)

	response = response[37:]

	res, err := attestation.ParseSpdmMeasurementResponseMessage(response, len(expectedSignature))

	assert.NoError(t, err)

	assert.Equal(t, uint8(0x11), res.SpdmVersion)
	assert.Equal(t, uint8(0x60), res.RequestResponseCode)
	assert.Equal(t, uint8(0x00), res.Param1)
	assert.Equal(t, uint8(0x00), res.Param2)
	assert.Equal(t, uint8(64), res.NumberOfBlocks)
	assert.Equal(t, 64, len(res.MeasurementRecords))

	//Crude check of records
	assert.Equal(t, len(res.MeasurementRecords), int(res.NumberOfBlocks))
	assert.Equal(t, expectedNonce, res.Nonce)

	//TODO verify OpaqueData

	assert.Equal(t, expectedSignature[:], res.Signature)
}
