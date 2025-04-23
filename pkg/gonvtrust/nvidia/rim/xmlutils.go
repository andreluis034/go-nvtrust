package rim

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/beevik/etree"
)

type dssSignature struct {
	R, S *big.Int
}

func rawSignatureToAsn1(rawSig []byte) []byte {
	r := big.NewInt(0).SetBytes(rawSig[:len(rawSig)/2])
	s := big.NewInt(0).SetBytes(rawSig[len(rawSig)/2:])
	sequence := dssSignature{r, s}
	signature, _ := asn1.Marshal(sequence)

	return signature
}
func fixSignatureValueWorkaround(sig *etree.Element) error {
	sigValueElem := sig.FindElement("SignatureValue")
	if sigValueElem == nil {
		return errors.New("could not find SignatureValue element")
	}
	if len(sigValueElem.Child) < 1 {
		return errors.New("no children for SignatureValue element")
	}
	data, ok := sigValueElem.Child[0].(*etree.CharData)
	if !ok {
		return errors.New("SignatureValue element does not contain character data")
	}
	rawSig, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		return err
	}
	data.Data = base64.StdEncoding.EncodeToString(rawSignatureToAsn1(rawSig))

	return nil
}

func fixXmlSignatureWorkaround(root *etree.Element, trustedCertificate *x509.Certificate) error {
	attrs := []etree.Attr{
		{
			Space: "xmlns",
			Key:   "ds",
			Value: "http://www.w3.org/2000/09/xmldsig#",
		},
	}
	if root == nil {
		return errors.New("could not find SoftwareIdentity element")
	}
	nodeSignature := root.FindElement("Signature")
	if nodeSignature == nil {
		return errors.New("could not find Signature element")
	}
	if _, ok := trustedCertificate.PublicKey.(*ecdsa.PublicKey); ok {
		err := fixSignatureValueWorkaround(nodeSignature)
		if err != nil {
			return err
		}
	}

	nodeSignedInfo := nodeSignature.FindElement("SignedInfo")
	if nodeSignedInfo == nil {
		return errors.New("could not find SignedInfo element")
	}

	for _, attr := range root.Attr {
		if attr.Space == "xmlns" || attr.Key == "xmlns" {
			attrs = append(attrs, attr)
		}
	}
	nodeSignedInfo.Attr = attrs

	return nil
}

func extractCertificatesFromXml(root *etree.Element) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	if root == nil {
		return nil, errors.New("could not find SoftwareIdentity element")
	}
	nodeSignature := root.FindElement("Signature")
	if nodeSignature == nil {
		return nil, errors.New("could not find Signature element")
	}
	nodeKeyInfo := nodeSignature.FindElement("KeyInfo")
	if nodeKeyInfo == nil {
		return nil, errors.New("could not find SignKeyInfoature element")
	}
	nodeX509Data := nodeKeyInfo.FindElement("X509Data")
	if nodeX509Data == nil {
		return nil, errors.New("could not find X509Data element")
	}
	for _, certElem := range nodeX509Data.FindElements("X509Certificate") {
		if len(certElem.Child) < 1 {
			continue
		}
		certData, ok := certElem.Child[0].(*etree.CharData)
		if !ok {
			continue
		}
		decodedCert, err := base64.StdEncoding.DecodeString(certData.Data)

		if err != nil {
			return nil, errors.New("failed to decode certificate: " + err.Error())
		}
		cert, err := x509.ParseCertificate(decodedCert)
		if err != nil {
			return nil, errors.New("failed to parse certificate: " + err.Error())
		}
		certs = append(certs, cert)
	}

	return certs, nil
}
