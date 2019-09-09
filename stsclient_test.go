package stsclient

import (
	"testing"
	"crypto/tls"
	"crypto/x509"

	"gotest.tools/assert"
	"encoding/pem"

       "encoding/xml"
        saml2 "github.com/russellhaering/gosaml2/types"

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

       	var assertion saml2.Assertion
        err = xml.Unmarshal([]byte(response.assertion), &assertion)
        assert.NilError(t, err, "Could not parse to assertion")
        assert.Equal(t, "CN=medcomsystemuser,O=Internet Widgits Pty Ltd,ST=Some-State,C=DK", assertion.Subject.NameID.Value)
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
	claimKey := "claim-a"
	claimValue := "whatever"
      	claims[claimKey] = claimValue

        // When
        response, err := subject.GetToken(audience, claims)

        assert.NilError(t, err)

        var assertion saml2.Assertion
        err = xml.Unmarshal([]byte(response.assertion), &assertion)
        assert.NilError(t, err, "Could not parse to assertion")
        assert.Equal(t, "CN=medcomsystemuser,O=Internet Widgits Pty Ltd,ST=Some-State,C=DK", assertion.Subject.NameID.Value)

	claimsReturned := make(map[string][]saml2.AttributeValue)
	for _, attribute := range assertion.AttributeStatement.Attributes {
		claimsReturned[attribute.Name] = attribute.Values
	}

	claimValues, containsClaimA := claimsReturned[claimKey]
	assert.Equal(t, true, containsClaimA)
	assert.Equal(t, 1, len(claimValues))
	assert.Equal(t, claimValue, claimValues[0].Value)

}

