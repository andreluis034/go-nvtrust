package attestation

import (
	"encoding/binary"
	"errors"
)

type DmtfMeasurement struct {
	// This fields defines what the measusurement represents
	// In practice NVIDIA seems to always set this to 1, meaning a raw bit stream of immutable rom
	ValueType uint8
	Value     []byte
}

type MeasurementRecord struct {
	Index       uint8
	MrSpec      uint8
	Measurement DmtfMeasurement
}

func ParseDmtfMeasurement(data []byte) (*DmtfMeasurement, error) {
	if len(data) < 3 {
		return nil, errors.New("data too short to be a valid DMTF measurement")
	}
	mrSize := binary.LittleEndian.Uint16(data[1:3])
	if len(data) < 3+int(mrSize) {
		return nil, errors.New("data too short to be a valid measurement record")
	}

	dmtf := &DmtfMeasurement{
		ValueType: data[0],
		Value:     make([]byte, mrSize),
	}

	copy(dmtf.Value, data[3:3+int(mrSize)])

	return dmtf, nil
}

func ParseMeasurement(data []byte) (*MeasurementRecord, int, error) {
	if len(data) < 4 {
		return nil, 0, errors.New("data too short to be a valid measurement record")
	}
	if data[1] != 0x01 { //measurementSpec
		// The spec currently only defines DMTF format, all other bits are reserved
		return nil, 0, errors.New("unsupported measurement specification")
	}

	mrSize := binary.LittleEndian.Uint16(data[2:4])
	if len(data) < 4+int(mrSize) {
		return nil, 0, errors.New("data too short to be a valid measurement record")
	}
	dmtf, err := ParseDmtfMeasurement(data[4 : 4+int(mrSize)])
	if err != nil {
		return nil, 0, err
	}
	return &MeasurementRecord{
		Index:       data[0],
		MrSpec:      data[1],
		Measurement: *dmtf,
	}, int(4 + mrSize), nil
}

func ParseAllMeasurements(data []byte) ([]MeasurementRecord, int, error) {
	records := []MeasurementRecord{}
	consumedTotal := 0

	for mr, consumed, err := ParseMeasurement(data); err == nil; mr, consumed, err = ParseMeasurement(data) {

		records = append(records, *mr)
		data = data[consumed:]

		consumedTotal += consumed
	}

	return records, consumedTotal, nil
}
