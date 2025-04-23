package verify

import (
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvidia/ocsp"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvidia/rim"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/verifier/attestation"
)

//go:embed nvidia_device_identity_ca.pem
var nvidiaDeviceIdentityCa []byte

type Options struct {
	Hash                 crypto.Hash
	TrustedGpuCas        *x509.CertPool
	TrustedRimCas        *x509.CertPool
	GetIntegrityManifest bool
	CheckOcsp            bool
	CurrentTime          time.Time
	HTTPSGetter          func(url string) (map[string][]string, []byte, error)

	manifest *Manifest
}

type Manifest struct {
	driver *rim.RimInfo
	vbios  *rim.RimInfo

	driverIdentity *rim.SoftwareIdentity
	vbiosIdentity  *rim.SoftwareIdentity
}

func httpsGetter(url string) (map[string][]string, []byte, error) {
	var header map[string][]string

	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	} else if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("failed to retrieve %s, status code received %d", url, resp.StatusCode)
	}

	header = resp.Header

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp.Body.Close()
	return header, body, nil
}

func GetNvidiaRootCa() *x509.CertPool {
	certPool := x509.NewCertPool()

	block, _ := pem.Decode(nvidiaDeviceIdentityCa)
	if block == nil {
		return certPool
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		certPool.AddCert(cert)
	}

	return certPool
}

func DefaultOptions() *Options {

	return &Options{
		Hash:          crypto.SHA384,
		HTTPSGetter:   httpsGetter,
		CurrentTime:   time.Now(),
		TrustedGpuCas: nil,
	}
}

func RawCcReport(rawReport []byte, gpuCertChain []*x509.Certificate, options *Options) error {
	report, err := attestation.ParseAttestationReport(rawReport, options.Hash.Size()*2)
	if err != nil {
		return err
	}

	return CcReport(report, gpuCertChain, options)
}

func CcReport(report *attestation.AttestationReport, gpuCertChain []*x509.Certificate, options *Options) error {
	var err error
	if options.TrustedGpuCas == nil {
		options.TrustedGpuCas = GetNvidiaRootCa()
	}
	if options.TrustedRimCas == nil {
		options.TrustedRimCas = rim.GetNvidiaRimCa()
	}
	if options.GetIntegrityManifest {
		options.manifest, err = fetchIntegrityManifest(report, options)

		if err != nil {
			return err
		}
	}
	return verifyEvidence(report, gpuCertChain, options)
}

type GoldenMeasurement map[uint8]rim.Resource

func mergeMeasurements(vbios *rim.SoftwareIdentity, driver *rim.SoftwareIdentity) (GoldenMeasurement, error) {
	golden := make(GoldenMeasurement)

	for _, res := range vbios.Payload.Resources {
		if res.Active {
			golden[uint8(res.Index)] = res
		}
	}

	for _, res := range driver.Payload.Resources {
		if res.Active {
			_, ok := golden[uint8(res.Index)]
			if ok {
				return nil, fmt.Errorf("the vbios and the driver RIM have measurements at the same index: %d", res.Index)
			}
			golden[uint8(res.Index)] = res
		}
	}

	return golden, nil
}

func matchesAny(record *attestation.MeasurementRecord, golden *rim.Resource) bool {
	for _, goldenHash := range golden.Hashes {
		decodedGolden, err := hex.DecodeString(goldenHash)
		if err != nil {
			continue
		}
		if slices.Equal(record.Measurement.Value, decodedGolden) {
			return true
		}
	}
	return false
}

func verifyReportMeasurements(report *attestation.AttestationReport, vbios *rim.SoftwareIdentity, driver *rim.SoftwareIdentity) (err error) {
	golden, err := mergeMeasurements(vbios, driver)

	if err != nil {
		return
	}
	for _, goldenRecord := range golden {
		//Very counterintuitively the rim records start at index 0, but the records returned by the gpu start at 1
		//https://github.com/NVIDIA/nvtrust/blob/4d55e4f2abaf43de25e961a9ffc3576aa87bf07b/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/attestation/spdm_msrt_resp_msg.py#L173
		record, ok := report.ResponseMessage.MeasurementRecords[uint8(goldenRecord.Index+1)]

		if !ok {
			return fmt.Errorf("rim wants measurement at index %d, but not present in the report", goldenRecord.Index)
		}
		if !report.ResponseMessage.IsMeasurementValid(int(record.Index)) {
			continue
		}
		if !matchesAny(&record, &goldenRecord) {
			return fmt.Errorf("failed to verify measurement at index %d", record.Index)
		}
	}

	return nil
}

func verifyAttestationReport(report *attestation.AttestationReport, signingCert *x509.Certificate, options *Options) (err error) {
	if !report.VerifySignature(signingCert, crypto.SHA384.New()) {
		return errors.New("failed to verify attestation report signature")
	}
	if options.GetIntegrityManifest {
		driverVersion := report.ResponseMessage.OpaqueData.GetDataAsString(attestation.OpaqueFieldID_DriverVersion)
		if driverVersion != options.manifest.driverIdentity.Meta.ColloquialVersion {
			return errors.New("driver version in the report does not math the version from the rim manifest")
		}
		vBiosVersion := FormatVbiosVersion(report.ResponseMessage.OpaqueData.Fields[attestation.OpaqueFieldID_VbiosVersion].([]byte))
		if vBiosVersion != options.manifest.vbiosIdentity.Meta.ColloquialVersion {
			return errors.New("driver version in the report does not math the version from the rim manifest")
		}
		if err = verifyReportMeasurements(report, options.manifest.vbiosIdentity, options.manifest.driverIdentity); err != nil {
			return
		}
	}

	return nil
}

func verifyOcsp(gpuCertChain []*x509.Certificate, options *Options) (err error) {
	getter := ocsp.HTTTPostImpl{}

	if err = ocsp.VerifyChainStatus(gpuCertChain, getter); err != nil {
		return
	}
	if options.GetIntegrityManifest {
		driverChain := options.manifest.driverIdentity.GetCertificates()
		if driverChain == nil {
			return errors.New("failed to extract certificates from driver rim")
		}

		vbiosChain := options.manifest.vbiosIdentity.GetCertificates()
		if driverChain == nil {
			return errors.New("failed to extract certificates from driver rim")
		}

		if err = ocsp.VerifyChainStatus(driverChain, getter); err != nil {
			return
		}
		if err = ocsp.VerifyChainStatus(vbiosChain, getter); err != nil {
			return
		}
	}

	return nil
}

func verifyEvidence(report *attestation.AttestationReport, gpuCertChain []*x509.Certificate, options *Options) (err error) {
	if report.RequestMessage.SpdmVersion != report.ResponseMessage.SpdmVersion {
		return fmt.Errorf("spdm request version does not match spdm response version")
	}
	if report.RequestMessage.SpdmVersion != 0x11 {
		return fmt.Errorf("unsupported spdm version %d", report.RequestMessage.SpdmVersion)
	}
	if err = verifyGpuCertChain(gpuCertChain, options); err != nil {
		return
	}

	if options.GetIntegrityManifest {
		opts := rim.RimInfoVerificationOptions{
			CurrentTime: options.CurrentTime,
			RootCA:      options.TrustedRimCas,
		}
		options.manifest.driverIdentity, err = options.manifest.driver.Verify(&opts)
		if err != nil {
			return
		}
		options.manifest.vbiosIdentity, err = options.manifest.vbios.Verify(&opts)
		if err != nil {
			return
		}
	}
	if options.CheckOcsp {
		if err = verifyOcsp(gpuCertChain, options); err != nil {
			return err
		}

	}
	//We have verified the above chain against NVIDIA's root CA, so we can trust the leaf certificate
	return verifyAttestationReport(report, gpuCertChain[0], options)
}

func verifyGpuCertChain(certChain []*x509.Certificate, options *Options) error {
	if len(certChain) < 1 {
		return errors.New("zero size gpu cert chain")
	}
	leaf := certChain[0]
	intermediate := certChain[1 : len(certChain)-1]

	interPool := x509.NewCertPool()
	for i := 0; i < len(intermediate); i++ {
		interPool.AddCert(intermediate[i])
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         options.TrustedGpuCas,
		Intermediates: interPool,
		CurrentTime:   options.CurrentTime,
	})

	return err
}

func fetchIntegrityManifest(report *attestation.AttestationReport, options *Options) (*Manifest, error) {
	vbiosVersion := strings.ToUpper(
		strings.ReplaceAll(
			FormatVbiosVersion(report.ResponseMessage.OpaqueData.Fields[attestation.OpaqueFieldID_VbiosVersion].([]byte)),
			".",
			""))
	opaque := report.ResponseMessage.OpaqueData
	driverUrl := rim.RimDriverUrl("GH100", opaque.GetDataAsString(attestation.OpaqueFieldID_DriverVersion))
	vbiosUrl := rim.RimVbiosUrl(
		opaque.GetDataAsString(attestation.OpaqueFieldID_Project),
		opaque.GetDataAsString(attestation.OpaqueFieldID_ProjectSku),
		opaque.GetDataAsString(attestation.OpaqueFieldID_ChipSku),
		vbiosVersion)

	_, bodyDriver, errDriver := options.HTTPSGetter(driverUrl)
	_, bodyVbios, errBios := options.HTTPSGetter(vbiosUrl)

	if errBios != nil || errDriver != nil {
		return nil, errors.New("failed to fetch rim information")
	}
	var driverRimInfo, vbiosRimInfo rim.RimInfo
	errDriver = json.Unmarshal(bodyDriver, &driverRimInfo)
	errBios = json.Unmarshal(bodyVbios, &vbiosRimInfo)
	if errDriver != nil || errBios != nil {
		return nil, errors.New("failed to unmarshal rim information")
	}

	return &Manifest{
		driver: &driverRimInfo,
		vbios:  &vbiosRimInfo,
	}, nil
}
