package stsclient

import (
	"testing"
	"crypto/tls"
//	"encoding/pem"
//        "github.com/russellhaering/gosaml2/types"

//	"fmt"
 	"gotest.tools/assert"
  	dsig "github.com/russellhaering/goxmldsig"
//	"io/ioutil"
)

func TestGetStsRequestNoSignature(t *testing.T) {

	// Given
	clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore)


	// When
	request, err := subject.CreateStsRequest(false)

	// Given
//	clientCert, err := ioutil.ReadFile("./testdata/client.crt")
//	block, _ := pem.Decode([]byte(clientCert))
//	cert, err := x509.ParseCertificate(block.Bytes)
//	context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
 //       	Roots: []*x509.Certificate { cert },
 //   	})

   /*     subject := NewTokenAuthenticator(context)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")

	// When
	assertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(bs) 
*/
	// Then
	s, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")
	assert.Equal(t, "1.0", s)
//	assert.Equal(t, assertion.Version, "2.0")
//	assert.Equal(t, len(assertion.AttributeStatement.Attributes), 4)
	// TODO: tjek flere
}

func TestGetStsRequestSigned(t *testing.T) {

        // Given
        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore)


        // When
        request, err := subject.CreateStsRequest(true)


	// Then
	s, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "Error creating request")
	assert.Equal(t, "1.0", s)

}




// Testcase med forkert udsteder

// Testcase

