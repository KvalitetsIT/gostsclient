package stsclient

import (
	"io/ioutil"

	"encoding/xml"
	saml2 "github.com/russellhaering/gosaml2/types"

        "testing"
	"gotest.tools/assert"
)

func TestHandleResponsePayload(t *testing.T) {

	// Given
	payload, _ := ioutil.ReadFile("./testdata/sts_response_payload.xml")

	// When
	result, err := HandleStsResponsePayload(payload)

	// Then
	assert.NilError(t, err, "No error expected")

	var assertion saml2.Assertion
	err = xml.Unmarshal([]byte(result), &assertion)
	assert.NilError(t, err, "Could not parse to assertion")
        assert.Equal(t, "CN=medcomsystemuser,O=Internet Widgits Pty Ltd,ST=Some-State,C=DK", assertion.Subject.NameID.Value)
}

