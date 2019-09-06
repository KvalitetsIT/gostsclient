package stsclient

import (
	"testing"
	"crypto/tls"
	"crypto/x509"

	"gotest.tools/assert"
	"encoding/pem"

//        "github.com/russellhaering/gosaml2/types"

//  	"github.com/russellhaering/goxmldsig"
	"io/ioutil"
)

func TestGetToken(t *testing.T) {

	// Given
	stsCert, _ := ioutil.ReadFile("./testenv/sts/sts.cer")
      	stsBlock, _ := pem.Decode([]byte(stsCert))
    	stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	subject, _ := NewStsClient(stsCertToTrust, &clientKeyPair, "https://sts/sts/service/sts")

	// When
	response, err := subject.GetToken()

	assert.NilError(t, err)
        assert.Equal(t, "2.0", response.ToString())



	// Given
//	clientCert, err := ioutil.ReadFile("./testdata/client.crt")
//	block, _ := pem.Decode([]byte(clientCert))
//	cert, err := x509.ParseCertificate(block.Bytes)
//	context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
 //       	Roots: []*x509.Certificate { cert },
 //   	})

   /*     subject := NewTokenAuthenticator(context)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")

	// When
	assertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(bs) 

	// Then
	assert.NilError(t, errProcess)
	assert.Equal(t, assertion.Version, "2.0")
	assert.Equal(t, len(assertion.AttributeStatement.Attributes), 4)
	// TODO: tjek flere*/
}




// Testcase med forkert udsteder

// Testcase

