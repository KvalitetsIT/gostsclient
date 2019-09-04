package stsclient

import (
	"testing"
	"crypto/tls"

	"gotest.tools/assert"
//	"encoding/pem"
//        "github.com/russellhaering/gosaml2/types"

 //	"gotest.tools/assert"
//  	"github.com/russellhaering/goxmldsig"
//	"io/ioutil"
)

func TestGetToken(t *testing.T) {

	// Given
        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	subject, _ := NewStsClient(&clientKeyPair, "https://sts.test-vdxapi.vconf.dk/sts/service/sts")

	// When
	assertion, err :=subject.GetToken()
	assert.NilError(t, err)
        assert.Equal(t, "2.0", assertion)



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

