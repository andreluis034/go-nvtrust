package rim

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

//go:embed nvidia_corim_signing_ca.pem
var NvidiaCorimSigningCa []byte

const (
	RimBaseURL = "https://rim.attestation.nvidia.com/v1/rim"
)

type RimInfo struct {
	Id          string `json:"id"`
	Rim         []byte `json:"rim"`
	Sha256      string `json:"sha256"`
	LastUpdated string `json:"last_updated"`
	RimFormat   string `json:"rim_format"`
	RequestId   string `json:"request_id"`
}

type SoftwareIdentity struct {
	Corpus       bool    `xml:"corpus,attr"`
	Name         string  `xml:"name,attr"`
	Patch        bool    `xml:"patch,attr"`
	Supplemental bool    `xml:"supplemental,attr"`
	TagID        string  `xml:"tagId,attr"`
	Version      string  `xml:"version,attr"`
	TagVersion   string  `xml:"tagVersion,attr"`
	Entity       Entity  `xml:"Entity"`
	Meta         Meta    `xml:"Meta"`
	Payload      Payload `xml:"Payload"`

	signingCertificates []*x509.Certificate
}

type Entity struct {
	Name string `xml:"name,attr"`
	Role string `xml:"role,attr"`
}

type Payload struct {
	Resources []Resource `xml:"Resource"`
}

type Meta struct {
	Edition           string     `xml:"edition,attr"`
	Product           string     `xml:"product,attr"`
	Revision          string     `xml:"revision,attr"`
	ColloquialVersion string     `xml:"colloquialVersion,attr"`
	Attrs             []xml.Attr `xml:",any,attr"`
}

type ResourceType string

const (
	ResourceTypeMeasurement = "Measurement"
)

type Resource struct {
	Type         ResourceType `xml:"type,attr"`
	Index        int          `xml:"index,attr"`
	Active       bool         `xml:"active,attr"`
	Alternatives int          `xml:"alternatives,attr"`
	Name         string       `xml:"name,attr"`
	Size         int          `xml:"size,attr"`
	Hashes       []string     `xml:"hash,attr"`
	// capture all hash attributes in a xml
	Attr []xml.Attr `xml:",any,attr"`
}

type resourceHack Resource

func (r *Resource) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var resource resourceHack
	err := d.DecodeElement(&resource, &start)
	if err != nil {
		return err
	}
	r.Type = resource.Type
	r.Index = resource.Index
	r.Active = resource.Active
	r.Alternatives = resource.Alternatives
	r.Name = resource.Name
	r.Size = resource.Size
	r.Hashes = []string{}

	for _, attr := range resource.Attr {
		if strings.HasPrefix(attr.Name.Local, "Hash") {
			r.Hashes = append(r.Hashes, attr.Value)
		}
	}

	return nil
}

type Signature struct {
	SignedInfo     SignedInfo `xml:"SignedInfo"`
	SignatureValue string     `xml:"SignatureValue"`
	KeyInfo        KeyInfo    `xml:"KeyInfo"`
}

type SignedInfo struct {
	XMLName xml.Name `xml:"SignedInfo"`
}

type KeyInfo struct {
	XMLName xml.Name `xml:"KeyInfo"`
}

type RimInfoVerificationOptions struct {
	CurrentTime time.Time
	RootCA      *x509.CertPool
}

func (s *SoftwareIdentity) GetCertificates() []*x509.Certificate {
	return s.signingCertificates
}

func GetNvidiaRimCa() *x509.CertPool {
	rootCertPool := x509.NewCertPool()

	block, _ := pem.Decode([]byte(NvidiaCorimSigningCa))
	if block != nil {
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			rootCertPool.AddCert(parsedCert)
		}
	}

	return rootCertPool
}

func DefaultRimInfoVerificationOptions() RimInfoVerificationOptions {

	return RimInfoVerificationOptions{
		CurrentTime: time.Now(),
		RootCA:      GetNvidiaRimCa(),
	}
}

func (info *RimInfo) Verify(options *RimInfoVerificationOptions) (*SoftwareIdentity, error) {
	if fmt.Sprintf("%x", sha256.Sum256(info.Rim)) != info.Sha256 {
		return nil, errors.New("hash verification of rim failed")
	}
	return VerifyRimTcgSignature(string(info.Rim), options)
}

func verifyCertificateChain(rootPool *x509.CertPool, intermediateCA []*x509.Certificate, leaf *x509.Certificate, time time.Time) error {
	inter := x509.NewCertPool()
	for i := 0; i < len(intermediateCA); i++ {
		inter.AddCert(intermediateCA[i])
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: inter,
		Roots:         rootPool,
		CurrentTime:   time,
	})
	return err
}

func VerifyRimTcgSignature(rim string, options *RimInfoVerificationOptions) (*SoftwareIdentity, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(rim)
	if err != nil {
		return nil, err
	}

	rootElem := doc.Root()

	certs, err := extractCertificatesFromXml(rootElem)
	if err != nil {
		return nil, err
	}

	if err = verifyCertificateChain(options.RootCA, certs[1:len(certs)-1], certs[0], options.CurrentTime); err != nil {
		return nil, err
	}

	//TODO open an issue in github.com/russellhaering/goxmldsig
	err = fixXmlSignatureWorkaround(rootElem, certs[0])
	if err != nil {
		return nil, err
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{certs[0]},
	})

	validated, err := ctx.Validate(rootElem)
	if err != nil {
		return nil, err
	}

	var identity SoftwareIdentity
	validatedDoc := etree.NewDocument()
	validatedDoc.SetRoot(validated)

	xmlBytes, err := validatedDoc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(xmlBytes, &identity)
	if err != nil {
		return nil, err
	}

	identity.signingCertificates = certs

	return &identity, nil
}

func RimDriverUrl(gpuModel, driverVersion string) string {
	return fmt.Sprintf("%s/NV_GPU_DRIVER_%s_%s", RimBaseURL, gpuModel, driverVersion)
}

func RimVbiosUrl(project, projectSku, ChipSku, vbiosVersion string) string {
	return fmt.Sprintf("%s/NV_GPU_VBIOS_%s_%s_%s_%s", RimBaseURL, project, projectSku, ChipSku, vbiosVersion)
}
