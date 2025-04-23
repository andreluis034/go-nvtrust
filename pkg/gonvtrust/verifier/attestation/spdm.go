package attestation

import (
	"errors"
)

type SpdmMeasurementRequestMessage struct {
	SpdmVersion         uint8
	RequestResponseCode uint8
	Param1              uint8
	Param2              uint8
	Nonce               [32]byte
	SlotIDParam         uint8
}

func ParseSpdmMeasurementRequestMessage(data []byte) (*SpdmMeasurementRequestMessage, error) {
	if len(data) < 37 {
		return nil, errors.New("data too short to be a valid SPDM MEASUREMENTS request")
	}

	message := &SpdmMeasurementRequestMessage{
		SpdmVersion:         data[0],
		RequestResponseCode: data[1],
		Param1:              data[2],
		Param2:              data[3],
		Nonce:               [32]byte{},
		SlotIDParam:         data[36],
	}

	copy(message.Nonce[:], data[4:36])

	return message, nil
}

type SpdmMeasurementResponseMessage struct {
	SpdmVersion         uint8
	RequestResponseCode uint8
	Param1              uint8
	Param2              uint8
	NumberOfBlocks      uint8
	MeasurementRecords  map[uint8]MeasurementRecord
	Nonce               [32]byte
	OpaqueData          OpaqueData
	Signature           []byte
}

func (r *SpdmMeasurementResponseMessage) IsMeasurementValid(index int) bool {
	if index != 36 {
		return true
	}

	nvdec_status, ok := r.OpaqueData.Fields[OpaqueFieldID_Nvdec0Status].([]byte)

	if !ok || len(nvdec_status) == 0 { // opaque data does not exist, so assume nvdec is disabled
		return false
	}

	return NVDecStatus(nvdec_status[0]) == NVDecStatus_Enabled
}

func ParseSpdmMeasurementResponseMessage(data []byte, signatureLength int) (*SpdmMeasurementResponseMessage, error) {
	if len(data) < 42+signatureLength {
		return nil, errors.New("data too short to be a valid SPDM MEASUREMENTS response")
	}
	mrRecordLength := int(data[5]) | int(data[6])<<8 | int(data[7])<<16
	opaqueLength := int(data[8+mrRecordLength+32]) | int((data[8+mrRecordLength+32+1]))<<8

	message := &SpdmMeasurementResponseMessage{
		SpdmVersion:         data[0],
		RequestResponseCode: data[1],
		Param1:              data[2],
		Param2:              data[3],
		NumberOfBlocks:      data[4],
		MeasurementRecords:  make(map[uint8]MeasurementRecord),
		Nonce:               [32]byte{},
		Signature:           make([]byte, signatureLength),
	}
	mrRecords := data[8 : 8+mrRecordLength]
	records, _, err := ParseAllMeasurements(mrRecords)
	if err != nil {
		return nil, err
	}
	if len(records) < int(message.NumberOfBlocks) {
		return nil, errors.New("number of parsed blocks does not match the number of measurement records")
	}
	for _, record := range records {
		message.MeasurementRecords[record.Index] = record
	}

	copy(message.Nonce[:], data[8+mrRecordLength:40+mrRecordLength])

	message.OpaqueData = ParseOpaqueData(data[42+mrRecordLength : 42+mrRecordLength+opaqueLength])

	copy(message.Signature, data[42+mrRecordLength+opaqueLength:42+signatureLength+mrRecordLength+opaqueLength])

	return message, nil
}
