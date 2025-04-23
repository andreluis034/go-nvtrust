package attestation

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type NVDecStatus uint8

const (
	NVDecStatus_Disabled = 0x55
	NVDecStatus_Enabled  = 0xAA
)

type OpaqueFieldID uint16

const (
	_ OpaqueFieldID = iota
	OpaqueFieldID_CertIssuerName
	OpaqueFieldID_CertAuthorityKeyIdentifier
	OpaqueFieldID_DriverVersion
	OpaqueFieldID_GpuInfo
	OpaqueFieldID_Sku
	OpaqueFieldID_VbiosVersion
	OpaqueFieldID_ManufacturerID
	OpaqueFieldID_TamperDetection
	OpaqueFieldID_Smc
	OpaqueFieldID_Vpr
	OpaqueFieldID_Nvdec0Status
	OpaqueFieldID_Msrscnt
	OpaqueFieldID_CprInfo
	OpaqueFieldID_BoardID
	OpaqueFieldID_ChipSku
	OpaqueFieldID_ChipSkuMod
	OpaqueFieldID_Project
	OpaqueFieldID_ProjectSku
	OpaqueFieldID_ProjectSkuMod
	OpaqueFieldID_Fwid
	OpaqueFieldID_ProtectedPcieStatus
	OpaqueFieldID_SwitchPdi
	OpaqueFieldID_FloorsweptPorts
	OpaqueFieldID_PositionID
	OpaqueFieldID_LockSwitchStatus
	OpaqueFieldID_GpuLinkConn
	OpaqueFieldID_SysEnableStatus
	OpaqueFieldID_OpaqueDataVersion
	OpaqueFieldID_Invalid OpaqueFieldID = 255
)

func (id OpaqueFieldID) String() string {
	switch id {
	case OpaqueFieldID_CertIssuerName:
		return "OpaqueFieldID_CertIssuerName"
	case OpaqueFieldID_CertAuthorityKeyIdentifier:
		return "OpaqueFieldID_CertAuthorityKeyIdentifier"
	case OpaqueFieldID_DriverVersion:
		return "OpaqueFieldID_DriverVersion"
	case OpaqueFieldID_GpuInfo:
		return "OpaqueFieldID_GpuInfo"
	case OpaqueFieldID_Sku:
		return "OpaqueFieldID_Sku"
	case OpaqueFieldID_VbiosVersion:
		return "OpaqueFieldID_VbiosVersion"
	case OpaqueFieldID_ManufacturerID:
		return "OpaqueFieldID_ManufacturerID"
	case OpaqueFieldID_TamperDetection:
		return "OpaqueFieldID_TamperDetection"
	case OpaqueFieldID_Smc:
		return "OpaqueFieldID_Smc"
	case OpaqueFieldID_Vpr:
		return "OpaqueFieldID_Vpr"
	case OpaqueFieldID_Nvdec0Status:
		return "OpaqueFieldID_Nvdec0Status"
	case OpaqueFieldID_Msrscnt:
		return "OpaqueFieldID_Msrscnt"
	case OpaqueFieldID_CprInfo:
		return "OpaqueFieldID_CprInfo"
	case OpaqueFieldID_BoardID:
		return "OpaqueFieldID_BoardID"
	case OpaqueFieldID_ChipSku:
		return "OpaqueFieldID_ChipSku"
	case OpaqueFieldID_ChipSkuMod:
		return "OpaqueFieldID_ChipSkuMod"
	case OpaqueFieldID_Project:
		return "OpaqueFieldID_Project"
	case OpaqueFieldID_ProjectSku:
		return "OpaqueFieldID_ProjectSku"
	case OpaqueFieldID_ProjectSkuMod:
		return "OpaqueFieldID_ProjectSkuMod"
	case OpaqueFieldID_Fwid:
		return "OpaqueFieldID_Fwid"
	case OpaqueFieldID_ProtectedPcieStatus:
		return "OpaqueFieldID_ProtectedPcieStatus"
	case OpaqueFieldID_SwitchPdi:
		return "OpaqueFieldID_SwitchPdi"
	case OpaqueFieldID_FloorsweptPorts:
		return "OpaqueFieldID_FloorsweptPorts"
	case OpaqueFieldID_PositionID:
		return "OpaqueFieldID_PositionID"
	case OpaqueFieldID_LockSwitchStatus:
		return "OpaqueFieldID_LockSwitchStatus"
	case OpaqueFieldID_GpuLinkConn:
		return "OpaqueFieldID_GpuLinkConn"
	case OpaqueFieldID_SysEnableStatus:
		return "OpaqueFieldID_SysEnableStatus"
	case OpaqueFieldID_OpaqueDataVersion:
		return "OpaqueFieldID_OpaqueDataVersion"
	case OpaqueFieldID_Invalid:
		return "OpaqueFieldID_Invalid"
	}
	return fmt.Sprintf("OpaqueFieldID_Unknown%d", id)
}

// This is a class to represent the OpaqueData field in the SPDM GET_MEASUREMENT response message.
// The structure of the data in this field is as follows:
// [DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)][DataType(2 bytes)|DataSize(2 bytes)|Data(DataSize bytes)]...
type OpaqueData struct {
	MeasurementCount []uint32
	Fields           map[OpaqueFieldID]any
}

func (od OpaqueData) GetDataAsString(field OpaqueFieldID) string {
	return string(bytes.Trim(od.Fields[field].([]byte), "\x00"))
}

func parseMeasurementCount(data []byte) []uint32 {
	out := []uint32{}
	if len(data)%4 != 0 {
		return out
	}

	for i := 0; i < len(data); i += 4 {
		out = append(out, binary.LittleEndian.Uint32(data[i:]))
	}

	return out
}

func ParseOpaqueData(data []byte) (od OpaqueData) {
	od.Fields = make(map[OpaqueFieldID]any)
	od.MeasurementCount = []uint32{}

	for i := 0; i < len(data); {
		dataType := OpaqueFieldID(binary.LittleEndian.Uint16(data[i : i+2]))
		dataSize := binary.LittleEndian.Uint16(data[i+2 : i+4])
		dataValue := data[i+4 : i+4+int(dataSize)]

		if dataType == OpaqueFieldID_Msrscnt {
			od.MeasurementCount = parseMeasurementCount(dataValue)
		} else if dataType == OpaqueFieldID_SwitchPdi {
			//TODO Is this used by anyone/anywhere?
		}
		od.Fields[dataType] = data[i+4 : i+4+int(dataSize)]
		fmt.Printf("%s(%d) = %x (%s)\n", dataType, dataType, dataValue, string(dataValue))
		i += 4 + int(dataSize)
	}

	return
}
