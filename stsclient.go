package stsclient

import (
	"net/http"
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"encoding/pem"
	"io/ioutil"
//	"fmt"
	dsig "github.com/russellhaering/goxmldsig"
)

type StsClient struct {

	clientKeyPair		*tls.Certificate
	PublicKey		*rsa.PublicKey

	stsRequestFactory	*StsRequestFactory

	client			*http.Client

}

func NewStsClient(trust *x509.Certificate, certFile string, certKey string, issueUrl string) (*StsClient, error) {

      	keyPair, err := tls.LoadX509KeyPair(certFile, certKey)
	if (err != nil) {
		return nil, err
	}

	certFileContent, err := ioutil.ReadFile(certFile)
	if (err != nil) {
		return nil, err
	}
        certBlock, _ := pem.Decode([]byte(certFileContent))
        cert, err := x509.ParseCertificate(certBlock.Bytes)
        if (err != nil) {
                return nil, err
        }
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	// Setup HTTPS client
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(trust)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{ keyPair },
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	return NewStsClientWithHttpClient(client, &keyPair, rsaPublicKey, issueUrl)
}

func NewStsClientWithHttpClient(httpClient *http.Client, keyPair *tls.Certificate, publicKey *rsa.PublicKey, issueUrl string) (*StsClient, error) {

        keyStore := dsig.TLSCertKeyStore(*keyPair)
        stsRequestFactory, err := NewStsRequestFactory(keyStore, publicKey, issueUrl)
        if (err != nil) {
                return nil, err
        }

        stsClient := StsClient{ clientKeyPair: keyPair, stsRequestFactory: stsRequestFactory, client: httpClient, PublicKey: publicKey }

        return &stsClient, nil
}


func (s StsClient) GetToken(appliesTo string, claims map[string]string) (*StsResponse, error) {

	// Create the SOAP request
	issueRequest, err := s.stsRequestFactory.CreateStsIssueRequest(appliesTo, claims)
	if (err != nil) {
                return nil, err
        }

	return s.request(issueRequest)
}


func (s StsClient) OnBehalfOf(appliesTo string, onBehalfOf []byte, claims map[string]string) (*StsResponse, error) {

	// Create the SOAP request
        issueRequest, err := s.stsRequestFactory.CreateOnBehalfOf(appliesTo, onBehalfOf, claims)
        if (err != nil) {
                return nil, err
        }

        return s.request(issueRequest)
}

func (s StsClient) ActAs(appliesTo string, actAs []byte, claims map[string]string) (*StsResponse, error) {

        // Create the SOAP request
        issueRequest, err := s.stsRequestFactory.CreateActAs(appliesTo, actAs, claims)
        if (err != nil) {
                return nil, err
        }

        return s.request(issueRequest)
}


func (s StsClient) request(issueRequest *http.Request) (*StsResponse, error) {

	issueResp, err := s.client.Do(issueRequest)
        if (err != nil) {
                return nil, err
        }
//	responseBody, _ := ioutil.ReadAll(issueResp.Body)
//	return nil, fmt.Errorf(fmt.Sprintf("%s", string(responseBody)))
        stsResponse, err := ParseStsResponse(issueResp)

	return stsResponse, err
}

