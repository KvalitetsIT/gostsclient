package stsclient

import (
	"testing"
	"crypto/x509"

	"gotest.tools/assert"
	"encoding/pem"

       "encoding/xml"
        saml2 "github.com/russellhaering/gosaml2/types"

	"io/ioutil"
)

func IgnoreTestGetTokenFromVdxSts(t *testing.T) {

	// Given
	stsUrl := "https://sts.test-vdxapi.vconf.dk/sts/service/sts" 
	stsCertFile := "./testdata/sts_test-vdxapi_vconf_dk.crt" 
	audience := "urn:medcom:videoapi" 

	stsCert, _ := ioutil.ReadFile(stsCertFile)
      	stsBlock, _ := pem.Decode([]byte(stsCert))
    	stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

	subject, err := NewStsClient(stsCertToTrust, "./testdata/medcom.cer", "./testdata/medcom.pem", stsUrl)
	if (err != nil) {
		panic(err)
	}

	// When
	response, err := subject.GetToken(audience, nil)

	// Then
	assert.NilError(t, err)

       	var assertion saml2.Assertion
        err = xml.Unmarshal([]byte(response.assertion), &assertion)
        assert.NilError(t, err, "Could not parse to assertion")
        assert.Equal(t, "CN=medcomsystemuser,O=Internet Widgits Pty Ltd,ST=Some-State,C=DK", assertion.Subject.NameID.Value)
}

func TestOnBehalfOfTokenFromLocalTestSts(t *testing.T) {

        // Given
        stsUrl := "https://sts/sts/service/sts"
        stsCertFile := "./testenv/sts/sts.cer"
        audience := "urn:kit:testa:servicea"

        stsCert, _ := ioutil.ReadFile(stsCertFile)
        stsBlock, _ := pem.Decode([]byte(stsCert))
        stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        subject, err := NewStsClient(stsCertToTrust, "./testdata/medcom.cer", "./testdata/medcom.pem", stsUrl)
	if (err != nil) {
		panic(err)
	}

        claimsFirst := make(map[string]string)
	claimFirstKey := "claim-a"
	claimFirstValue := "whatever"
      	claimsFirst[claimFirstKey] = claimFirstValue

        responseFirst, err := subject.GetToken(audience, claimsFirst)
	if (err != nil) {
		panic(err)
	}
	firstToken := []byte(responseFirst.assertion)

        claimsSecond := make(map[string]string)
        claimSecondKey := "claim-b"
        claimSecondValue := "testing123"
        claimsSecond[claimSecondKey] = claimSecondValue

	// When
	response, err := subject.OnBehalfOf(audience, firstToken, claimsSecond)

	// Then
	assert.NilError(t, err, "Failed act as")
        var assertion saml2.Assertion
        err = xml.Unmarshal([]byte(response.assertion), &assertion)
        assert.NilError(t, err, "Could not parse to assertion")
        assert.Equal(t, "CN=medcomsystemuser,O=Internet Widgits Pty Ltd,ST=Some-State,C=DK", assertion.Subject.NameID.Value)
	claimsReturned := make(map[string][]saml2.AttributeValue)
	for _, attribute := range assertion.AttributeStatement.Attributes {
		claimsReturned[attribute.Name] = attribute.Values
	}

        claimSecondValues, containsClaimB := claimsReturned[claimSecondKey]
        assert.Equal(t, true, containsClaimB)
        assert.Equal(t, 1, len(claimSecondValues))
        assert.Equal(t, claimSecondValue, claimSecondValues[0].Value)

/* TODO fejl i STS?        claimFirstValues, containsClaimA := claimsReturned[claimFirstKey]
        assert.Equal(t, true, containsClaimA)
        assert.Equal(t, 1, len(claimFirstValues))
        assert.Equal(t, claimFirstValue, claimFirstValues[0].Value)
*/
}


func IgnoreTestGetTokenFromLocalTestSts(t *testing.T) {

        // Given
        stsUrl := "https://sts/sts/service/sts"
        stsCertFile := "./testenv/sts/sts.cer"
        audience := "urn:kit:testa:servicea"

        stsCert, _ := ioutil.ReadFile(stsCertFile)
        stsBlock, _ := pem.Decode([]byte(stsCert))
        stsCertToTrust, _ := x509.ParseCertificate(stsBlock.Bytes)

        subject, err := NewStsClient(stsCertToTrust, "./testdata/medcom.cer", "./testdata/medcom.pem", stsUrl)
	if (err != nil) {
		panic(err)
	}

        claims := make(map[string]string)
	claimKey := "claim-a"
	claimValue := "whatever"
      	claims[claimKey] = claimValue

        // When
        response, err := subject.GetToken(audience, claims)

	// Then
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

