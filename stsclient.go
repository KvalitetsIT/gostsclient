package stsclient

import (
	"fmt"
	"bytes"
//	"io"
	"io/ioutil"
	"net/http"
//	"encoding/xml"
//	"encoding/base64"
	"crypto/tls"
	"crypto/x509"
	saml2 "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
//	"github.com/russellhaering/goxmldsig/types"
//	"github.com/beevik/etree"
)

type StsClient struct {
	clientKeyPair		*tls.Certificate
	stsRequestFactory	*StsRequestFactory

	client			*http.Client

	issueUrl		string
}

func NewStsClient(keyPair *tls.Certificate, issueUrl string) (*StsClient, error) {

	keyStore := dsig.TLSCertKeyStore(*keyPair)
	stsRequestFactory, err := NewStsRequestFactory(keyStore)
	if (err != nil) {
		return nil, err
	}

	// Setup HTTPS client
	caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{ *keyPair },
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	stsClient := StsClient{ clientKeyPair: keyPair, stsRequestFactory: stsRequestFactory, client: client, issueUrl: issueUrl }

	return &stsClient, nil
}

func (s StsClient) GetToken() (*saml2.Assertion, error) {


	// Create the SOAP request
	stsRequest, err := s.stsRequestFactory.CreateStsRequest(false)
	if (err != nil) {
                return nil, err
        }

        soapStr, err := stsRequest.SoapEnvelope.WriteToString()
        if (err != nil) {
		return nil, err
        }

	issueRequest, err := http.NewRequest("POST", s.issueUrl, bytes.NewBuffer([]byte(soapStr)))
	issueRequest.Header.Set("SOAPAction=", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	if (err != nil) {
                return nil, err
        }

    	issueResp, err := s.client.Do(issueRequest)
        if (err != nil) {
                return nil, err
        }
	defer issueResp.Body.Close()
	body, err := ioutil.ReadAll(issueResp.Body)

        fmt.Println(body)

	return nil, nil
}
