package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
	goocsp "golang.org/x/crypto/ocsp"
)

const OCSP_URL = "https://ocsp.ndis.nvidia.com"

type HTTPPost interface {
	Post(url string, headers map[string]string, body []byte) (map[string][]string, []byte, error)
}

type HTTTPostImpl struct {
}

func (HTTTPostImpl) Post(url string, headers map[string]string, req_body []byte) (map[string][]string, []byte, error) {
	httpRequest, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(req_body))
	if err != nil {
		return nil, nil, err
	}

	for key, val := range headers {
		httpRequest.Header.Add(key, val)
	}
	httpClient := &http.Client{}

	resp, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, nil, err
	}

	resHeader := resp.Header

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp.Body.Close()
	return resHeader, body, nil
}

func VerifyChainStatus(certs []*x509.Certificate, post HTTPPost) error {
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		issuer := certs[i+1]

		if len(issuer.OCSPServer) == 0 {
			continue
		}
		request, err := goocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA384})
		if err != nil {
			return err
		}
		req_headers := map[string]string{
			"Content-Type": "application/ocsp-request",
			"Accept":       "application/ocsp-response",
		}
		_, body, err := post.Post(OCSP_URL, req_headers, request)
		if err != nil {
			return err
		}

		resp, err := goocsp.ParseResponse(body, issuer)
		if err != nil {
			continue
		}

		if resp.Status != goocsp.Good {
			return fmt.Errorf("certificate %s status not good (%d)", cert.Subject.CommonName, resp.Status)
		}
	}

	return nil
}
