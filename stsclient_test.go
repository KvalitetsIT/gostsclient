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

func TestGetTokenFromVdxSts(t *testing.T) {

	// Given
	stsUrl := "https://sts.test-vdxapi.vconf.dk/sts/service/sts" 
	stsCertFile := "./testdata/sts_test-vdxapi_vconf_dk.crt" 
	audience := "urn:medcom:videoapi" 

	stsCert, _ := ioutil.ReadFile(stsCertFile)
      	stsBlock, _ := pem.Decode([]byte(stsCert))
    	stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	subject, _ := NewStsClient(stsCertToTrust, &clientKeyPair, stsUrl)


	// When
	response, err := subject.GetToken(audience, nil)

	// Then
	assert.NilError(t, err)
        assert.Equal(t, "test: output the response for now", response.ToString())
}


func TestGetTokenFromLocalTestSts(t *testing.T) {

        // Given
        stsUrl := "https://sts/sts/service/sts"
        stsCertFile := "./testenv/sts/sts.cer"
        audience := "urn:kit:testa:servicea"

        stsCert, _ := ioutil.ReadFile(stsCertFile)
        stsBlock, _ := pem.Decode([]byte(stsCert))
        stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        subject, _ := NewStsClient(stsCertToTrust, &clientKeyPair, stsUrl)

        claims := make(map[string]string)
      	claims["claim-a"] = "whatever"

        // When
        response, err := subject.GetToken(audience, claims)

        assert.NilError(t, err)
        assert.Equal(t, "test: output the response for now", response.ToString())
}

