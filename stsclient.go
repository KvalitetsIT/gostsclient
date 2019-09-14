package stsclient

import (
	"net/http"
	"crypto/tls"
	"crypto/x509"
	dsig "github.com/russellhaering/goxmldsig"
)

type StsClient struct {

	clientKeyPair		*tls.Certificate

	stsRequestFactory	*StsRequestFactory

	client			*http.Client

}

func NewStsClient(trust *x509.Certificate, keyPair *tls.Certificate, issueUrl string) (*StsClient, error) {

	// Setup HTTPS client
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(trust)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{ *keyPair },
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	return NewStsClientWithHttpClient(client, keyPair, issueUrl)
}

func NewStsClientWithHttpClient(httpClient *http.Client, keyPair *tls.Certificate, issueUrl string) (*StsClient, error) {

        keyStore := dsig.TLSCertKeyStore(*keyPair)
        stsRequestFactory, err := NewStsRequestFactory(keyStore, issueUrl)
        if (err != nil) {
                return nil, err
        }

        stsClient := StsClient{ clientKeyPair: keyPair, stsRequestFactory: stsRequestFactory, client: httpClient }

        return &stsClient, nil
}


func (s StsClient) GetToken(appliesTo string, claims map[string]string) (*StsResponse, error) {

	// Create the SOAP request
	issueRequest, err := s.stsRequestFactory.CreateStsIssueRequest(appliesTo, claims)
	if (err != nil) {
                return nil, err
        }

    	issueResp, err := s.client.Do(issueRequest)
        if (err != nil) {
                return nil, err
        }
	stsResponse, err := ParseStsResponse(issueResp)

	return stsResponse, err
}
