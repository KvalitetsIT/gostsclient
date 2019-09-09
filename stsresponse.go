package stsclient

import (
	"net/http"
	"io/ioutil"
	"fmt"
	"strings"

	etree "github.com/beevik/etree"
)

type StsResponse struct {

	assertion	string

}

func ParseStsResponse(response *http.Response) (*StsResponse, error) {

	defer response.Body.Close()
        body, err := ioutil.ReadAll(response.Body)

	if (err != nil) {
		return nil, err
	}

	if (response.StatusCode != http.StatusOK) {
		fmt.Errorf("Response not OK (payload: %s)", body)
	}

	assertion, err := HandleStsResponsePayload(body)
	if (err != nil) {
		return nil, err
	}

	stsResponse := &StsResponse{ assertion: assertion }

	return stsResponse, nil
}

func HandleStsResponsePayload(payload []byte) (string, error) {

	responseDocument := etree.NewDocument()
	if err := responseDocument.ReadFromBytes(payload); err != nil {
		return "", err
	}

	// The root node must be the SOAP Envelope
	rootElement := responseDocument.Root()
	bodyXPathExpression := "/Envelope/Body" // If soap is the default namespace
	hasNameSpace, soapNamespace, _ := splitNameSpaceAndTag(rootElement)
	if (hasNameSpace) {
		bodyXPathExpression = fmt.Sprintf("/%s:Envelope/%s:Body", soapNamespace, soapNamespace)
	}
	bodyQueryResult := rootElement.FindElements(bodyXPathExpression)
	if (len(bodyQueryResult) != 1) {
		return "",  fmt.Errorf("No body element found in STS response (response payload: %s)", string(payload))
	}
	bodyElement := bodyQueryResult[0]

	// Now let's look further down
	bodyChildren := bodyElement.ChildElements()
	if (len(bodyChildren) != 1) {
		return "",  fmt.Errorf("Exactly one child element expected for the body")
	}

	requestTokenResponseCollectionElement := bodyChildren[0]
	requestedSecurityTokenXPathExpression := "RequestSecurityTokenResponseCollection/RequestSecurityTokenResponse/RequestedSecurityToken"
	hasNameSpace, trustNamespace, _ := splitNameSpaceAndTag(requestTokenResponseCollectionElement)
	if (hasNameSpace) {
		requestedSecurityTokenXPathExpression = fmt.Sprintf("/%s:RequestSecurityTokenResponseCollection/%s:RequestSecurityTokenResponse/%s:RequestedSecurityToken", trustNamespace, trustNamespace, trustNamespace)
	}
	requestedSecurityTokenQueryResult := bodyElement.FindElements(requestedSecurityTokenXPathExpression)
	if (len(requestedSecurityTokenQueryResult) != 1) {
		return "",  fmt.Errorf("No RequestedSecurityToken under the body element found in STS response (response payload: %s)", string(payload))
	}
	requestedSecurityTokenElement := requestedSecurityTokenQueryResult[0]

	// We expect exactly one child...and that is the assertion
	requestedSecurityTokenElementChildren := requestedSecurityTokenElement.ChildElements()
        if (len(requestedSecurityTokenElementChildren) != 1) {
                return "",  fmt.Errorf("Exactly one child element expected for the RequestedSecurityToken")
        }
	assertionElement := requestedSecurityTokenElementChildren[0]

	// Copy the assertionElement from the response to create a new document
	assertionDocument := etree.NewDocument()
	assertionDocument.SetRoot(assertionElement.Copy())

	assertionStr, err := assertionDocument.WriteToString()
	if (err != nil) {
		return "", err
	}
	return assertionStr, nil
}

func splitNameSpaceAndTag(element *etree.Element) (bool, string, string) {
	elementTagSlice := strings.Split(element.Tag, ":")
        if (len(elementTagSlice) == 2) {
		return true, elementTagSlice[0], elementTagSlice[1]
        }

	return false, "", element.Tag
}

func (resp *StsResponse) ToString() string {
	return resp.assertion
}
