package stsclient

import (
	etree "github.com/beevik/etree"
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"
	"net/http"
	"encoding/base64"
	dsig "github.com/russellhaering/goxmldsig"
	uuid "github.com/google/uuid"
)

const id_attr			= "wsu:Id"
const namespace_default	= "xmlns"
const namespace_adr		= "xmlns:adr"
const namespace_ds		= "xmlns:ds"
const namespace_ic		= "xmlns:ic"
const namespace_saml2	= "xmlns:saml2"
const namespace_soap	= "xmlns:soap"
const namespace_wsu		= "xmlns:wsu"
const namespace_wst		= "xmlns:wst"
const namespace_wst14	= "xmlns:wst14"
const namespace_wsse	= "xmlns:wsse"
const namespace_wsp		= "xmlns:wsp"
const namespace_xsi		= "xmlns:xsi"
const namespace_wsfed   = "xmlns:wsfed"

const uri_adr			= "http://www.w3.org/2005/08/addressing"
const uri_ds			= "http://www.w3.org/2000/09/xmldsig#"
const uri_ic			= "http://schemas.xmlsoap.org/ws/2005/05/identity"
const uri_saml2			= "urn:oasis:names:tc:SAML:2.0:assertion"
const uri_soap_12		= "http://www.w3.org/2003/05/soap-envelope"
const uri_soap_11       = "http://schemas.xmlsoap.org/soap/envelope/"
const uri_wsu 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const uri_wst			= "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const uri_wst14			= "http://docs.oasis-open.org/ws-sx/ws-trust/200802"
const uri_wsse			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
const uri_wsp_12 	    = "http://schemas.xmlsoap.org/ws/2004/09/policy"
const uri_wsp_11        = "http://www.w3.org/ns/ws-policy"
const uri_xsi			= "http://www.w3.org/2001/XMLSchema-instance"
const uri_wsfed  		= "http://docs.oasis-open.org/wsfed/authorization/200706"

type StsRequest struct {

	SoapEnvelope		*etree.Document
}

type StsRequestFactory struct {

	keyStore		dsig.TLSCertKeyStore
	PublicKey       *rsa.PublicKey
	stsUrl			string
	claimDialect    string
	hash 			crypto.Hash

	requestCreator  func (factory *StsRequestFactory, appliesToAddress string, delegation *DelegationInfo, claims map[string]string) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element, *etree.Element, func(*etree.Element))
}


func NewStsRequestFactoryForKombit(keyStore dsig.TLSCertKeyStore, publicKey *rsa.PublicKey, stsUrl string) (*StsRequestFactory, error) {

	stsRequestFactory := StsRequestFactory{ keyStore: keyStore, stsUrl: stsUrl, PublicKey: publicKey, claimDialect: "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims", hash: crypto.SHA256, requestCreator: createIssueRequest12}

	return &stsRequestFactory, nil

}

func NewStsRequestFactory(keyStore dsig.TLSCertKeyStore, publicKey *rsa.PublicKey, stsUrl string) (*StsRequestFactory, error) {

	stsRequestFactory := StsRequestFactory{ keyStore: keyStore, stsUrl: stsUrl, PublicKey: publicKey, claimDialect: DEFAULT_CLAIMDIALECT, hash: crypto.SHA1, requestCreator: createIssueRequest}

	return &stsRequestFactory, nil
}

func (factory *StsRequestFactory) CreateStsIssueRequest(appliesTo string, claims map[string]string) (*http.Request, error) {
	return factory.createRequest(appliesTo, nil, claims, true)
}


func (factory *StsRequestFactory) CreateOnBehalfOf(appliesTo string, onBehalfOf []byte, claims map[string]string) (*http.Request, error) {

	di, err := createDelegationInfo(onBehalfOf, "wst:OnBehalfOf")
	if (err != nil) {
		return nil, err
	}

	return factory.createRequest(appliesTo, di, claims, true)
}

func (factory *StsRequestFactory) CreateActAs(appliesTo string, actAs []byte, claims map[string]string) (*http.Request, error) {

	di, err := createDelegationInfo(actAs, "wst14:ActAs")
	if (err != nil) {
		return nil, err
	}

	return factory.createRequest(appliesTo, di, claims, true)
}


func (factory *StsRequestFactory) createRequest(appliesTo string, delegationInfo *DelegationInfo, claims map[string]string, sign bool) (*http.Request, error) {
	stsRequest, err := factory.CreateStsRequest(appliesTo, claims, delegationInfo, true)
	if (err != nil) {
		return nil, err
	}

	soapStr, err := stsRequest.SoapEnvelope.WriteToString()
	if (err != nil) {
		return nil, err
	}

	fmt.Println("SOAP:", soapStr)

	issueRequest, err := http.NewRequest("POST", factory.stsUrl, bytes.NewBuffer([]byte(soapStr)))
	issueRequest.Header.Set("SOAPAction", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	issueRequest.Header.Set("Content-Type", "application/soap+xml; charset=utf-8" )

	return issueRequest, nil
}

func (factory *StsRequestFactory) CreateStsRequest(appliesTo string, claims map[string]string, delegationInfo *DelegationInfo, sign bool) (*StsRequest, error) {

	var inputElementCopy *etree.Element
	if (delegationInfo != nil) {
		inputElementCopy = delegationInfo.CopyElement()
	}

	soapEnvelope, securityElement, soapBody, headersToSign, delegationElement, keyInfoDecorator := factory.requestCreator(factory, appliesTo, delegationInfo, claims)

	if (sign) {
		request, err2 := factory.signSoapRequest(soapEnvelope, securityElement, soapBody, headersToSign, keyInfoDecorator, factory.hash)
		signedEnvelope, err := request, err2
		if (err != nil) {
			return nil, err
		}
		soapEnvelope = signedEnvelope
	}

	if (delegationElement != nil) {
		delegationElement.RemoveChildAt(0)
		delegationElement.AddChild(inputElementCopy)
	}

	stsRequest := StsRequest{ SoapEnvelope: soapEnvelope }
	return &stsRequest, nil
}

func addAttributesToSignableHeaderElement(headerElement *etree.Element, id string, uri_soap string) {

	headerElement.CreateAttr(namespace_adr, uri_adr)
	headerElement.CreateAttr(namespace_ds, uri_ds)
	headerElement.CreateAttr(namespace_saml2, uri_saml2)
	headerElement.CreateAttr(namespace_soap, uri_soap)
	headerElement.CreateAttr(namespace_wsse, uri_wsse)
	headerElement.CreateAttr(namespace_wsu, uri_wsu)
	headerElement.CreateAttr(namespace_xsi, uri_xsi)
	headerElement.CreateAttr(id_attr, id)
}

type DelegationInfo struct {

	DelegationElement	*etree.Element
	DelegationTagName	string
}

func createDelegationInfo(input []byte, tagName string) (*DelegationInfo, error) {

	doc := etree.NewDocument()
	err := doc.ReadFromBytes(input)
	if (err != nil) {
		return nil, err
	}
	inputElement := doc.Root()

	return &DelegationInfo{ DelegationElement: inputElement, DelegationTagName: tagName }, nil
}

func (di *DelegationInfo) CopyElement() *etree.Element {

	return di.DelegationElement.Copy()
}

// Det virker somom, at signeringen er meget følsom overfor namespace definitioner (noget med canonization), hvis du laver om i nedenstående, så test, at output kan
// verificeres på https://tools.chilkat.io/xmlDsigVerify.cshtml (ret tests til, så du får output)
func createIssueRequest(factory *StsRequestFactory, appliesToAddress string, delegation *DelegationInfo, claims map[string]string) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element, *etree.Element, func(*etree.Element)) {

	_, cert, err := factory.keyStore.GetKeyPair()
	if (err != nil) {
		panic(err)
	}

	modulusValue := base64.StdEncoding.EncodeToString(factory.PublicKey.N.Bytes())

	var delegationResult *etree.Element

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr(namespace_adr, uri_adr)
	envelope.CreateAttr(namespace_ds, uri_ds)
	envelope.CreateAttr(namespace_saml2, uri_saml2)
	envelope.CreateAttr(namespace_soap, uri_soap_11)
	envelope.CreateAttr(namespace_wsse, uri_wsse)
	envelope.CreateAttr(namespace_wsu, uri_wsu)
	envelope.CreateAttr(namespace_xsi, uri_xsi)

	header := envelope.CreateElement("soap:Header")
	header.CreateAttr(namespace_soap, uri_soap_11)

	action := header.CreateElement("adr:Action")
	action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	actionId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(action, actionId, uri_soap_11)

	messageId := header.CreateElement("adr:MessageID")
	messageId.SetText(fmt.Sprintf("urn:uuid:%s", uuid.New().String()))
	messageIdId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(messageId, messageIdId, uri_soap_11)

	to := header.CreateElement("adr:To")
	to.SetText(factory.stsUrl)
	toId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(to, toId, uri_soap_11)

	replyTo := header.CreateElement("adr:ReplyTo")
	replyToAddress := replyTo.CreateElement("adr:Address")
	replyToAddress.SetText("http://www.w3.org/2005/08/addressing/anonymous")
	replyToId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(replyTo, replyToId, uri_soap_11)

	security := header.CreateElement("wsse:Security")
	security.CreateAttr(namespace_ds, uri_ds)
	security.CreateAttr(namespace_wsse, uri_wsse)
	security.CreateAttr(namespace_wsu, uri_wsu)
	security.CreateAttr("soap:mustUnderstand", "1")

	timeStamp := security.CreateElement("wsu:Timestamp")
	timeStampId := fmt.Sprintf("TS-%s", uuid.New().String())
	addAttributesToSignableHeaderElement(timeStamp, timeStampId, uri_soap_11)

	cr := time.Now()
	created := timeStamp.CreateElement("wsu:Created")
	created.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", cr.Year(), cr.Month(), cr.Day(), cr.Hour(), cr.Minute(), cr.Second()))
	ex := cr.Add(time.Minute * 5)
	expires := timeStamp.CreateElement("wsu:Expires")
	expires.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", ex.Year(), ex.Month(), ex.Day(), ex.Hour(), ex.Minute(), ex.Second()))

	binarySecurityTokenValue := base64.StdEncoding.EncodeToString(cert)
	binarySecurityToken := security.CreateElement("wsse:BinarySecurityToken")
	binarySecurityTokenId := fmt.Sprintf("X509-%s", uuid.New().String())
	binarySecurityToken.CreateAttr(id_attr, binarySecurityTokenId)
	binarySecurityToken.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	binarySecurityToken.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	binarySecurityToken.SetText(binarySecurityTokenValue)

	keyInfoDecorator := func(keyInfo *etree.Element) {
		secTokenRef := keyInfo.CreateElement("wsse:SecurityTokenReference")
		reference := secTokenRef.CreateElement("wsse:Reference")
		reference.CreateAttr("URI", fmt.Sprintf("#%s", binarySecurityTokenId))
		reference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	}

	body := envelope.CreateElement("soap:Body")
	bodyId := fmt.Sprintf("_%s", uuid.New().String())
	body.CreateAttr(namespace_adr, uri_adr)
	body.CreateAttr(namespace_ds, uri_ds)
	body.CreateAttr(namespace_saml2, uri_saml2)
	body.CreateAttr(namespace_soap, uri_soap_11)
	body.CreateAttr(namespace_wsse, uri_wsse)
	body.CreateAttr(namespace_wst14, uri_wst14)
	body.CreateAttr(namespace_wsu, uri_wsu)
	body.CreateAttr(id_attr, bodyId)

	requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
	requestSecurityToken.CreateAttr(namespace_wst, uri_wst)

	requestType := requestSecurityToken.CreateElement("wst:RequestType")
	requestType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue")

	appliesTo := requestSecurityToken.CreateElement("wsp:AppliesTo")
	appliesTo.CreateAttr(namespace_wsp, uri_wsp_11)
	endpointRef := appliesTo.CreateElement("adr:EndpointReference")
	endpointRef.CreateAttr(namespace_adr, uri_adr)
	address := endpointRef.CreateElement("adr:Address")
	address.SetText(appliesToAddress)

	claimsElement := requestSecurityToken.CreateElement("wst:Claims")
	claimsElement.CreateAttr(namespace_ic, uri_ic)
	claimsElement.CreateAttr("Dialect", "http://schemas.xmlsoap.org/ws/2005/05/identity")
	for claimName, claimValue := range claims {

		claimValueElement := claimsElement.CreateElement("ic:ClaimValue")
		claimValueElement.CreateAttr("Uri", claimName)
		value := claimValueElement.CreateElement("ic:Value")
		value.SetText(claimValue)
	}

	tokenType := requestSecurityToken.CreateElement("wst:TokenType")
	tokenType.SetText("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")

	keyType := requestSecurityToken.CreateElement("wst:KeyType")
	keyType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey")

	useKey := requestSecurityToken.CreateElement("wst:UseKey")

	keyInfo := useKey.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr(namespace_ds, uri_ds)

	keyValue := keyInfo.CreateElement("ds:KeyValue")

	rsaKeyValue := keyValue.CreateElement("ds:RSAKeyValue")

	modulus := rsaKeyValue.CreateElement("ds:Modulus")
	modulus.SetText(modulusValue)

	exponent := rsaKeyValue.CreateElement("ds:Exponent")
	exponent.SetText("AQAB") // Most likely :-)

	if (delegation != nil) {
		delegationResult = requestSecurityToken.CreateElement(delegation.DelegationTagName)
		delegationResult.AddChild(delegation.CopyElement())
	}
	requestSecurityToken.CreateElement("wst:Renewing")
	return doc, security, body, []*etree.Element{ action, messageId, to, replyTo, timeStamp }, delegationResult, keyInfoDecorator
}


// Det virker somom, at signeringen er meget følsom overfor namespace definitioner (noget med canonization), hvis du laver om i nedenstående, så test, at output kan
// verificeres på https://tools.chilkat.io/xmlDsigVerify.cshtml (ret tests til, så du får output)
func  createIssueRequest12(factory *StsRequestFactory, appliesToAddress string, delegation *DelegationInfo, claims map[string]string) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element, *etree.Element, func(*etree.Element)) {

	_, cert, err := factory.keyStore.GetKeyPair()
	if (err != nil) {
		panic(err)
	}

	var delegationResult *etree.Element

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr(namespace_soap, uri_soap_12)

	header := envelope.CreateElement("soap:Header")

	action := header.CreateElement("Action")
	action.CreateAttr(namespace_default, uri_adr)
	action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	actionId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(action, actionId, uri_soap_12)

	messageId := header.CreateElement("MessageID")
	messageId.CreateAttr(namespace_default, uri_adr)
	messageId.SetText(fmt.Sprintf("urn:uuid:%s", uuid.New().String()))
	messageIdId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(messageId, messageIdId, uri_soap_12)

	to := header.CreateElement("To")
	to.CreateAttr(namespace_default, uri_adr)
	to.SetText(factory.stsUrl)
	toId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(to, toId, uri_soap_12)

	replyTo := header.CreateElement("ReplyTo")
	replyTo.CreateAttr(namespace_default, uri_adr)
	replyToAddress := replyTo.CreateElement("Address")
	replyToAddress.SetText("http://www.w3.org/2005/08/addressing/anonymous")
	replyToId := fmt.Sprintf("_%s", uuid.New().String())
	addAttributesToSignableHeaderElement(replyTo, replyToId, uri_soap_12)

	security := header.CreateElement("wsse:Security")
	security.CreateAttr(namespace_wsse, uri_wsse)
	security.CreateAttr(namespace_wsu, uri_wsu)
	security.CreateAttr("soap:mustUnderstand", "1")


	binarySecurityTokenValue := base64.StdEncoding.EncodeToString(cert)
	binarySecurityToken := security.CreateElement("wsse:BinarySecurityToken")
	binarySecurityTokenId := fmt.Sprintf("X509-%s", uuid.New().String())
	binarySecurityToken.CreateAttr(id_attr, binarySecurityTokenId)
	binarySecurityToken.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	binarySecurityToken.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	binarySecurityToken.SetText(binarySecurityTokenValue)
	addAttributesToSignableHeaderElement(binarySecurityToken, binarySecurityTokenId, uri_soap_12)

	timeStamp := security.CreateElement("wsu:Timestamp")
	timeStampId := fmt.Sprintf("TS-%s", uuid.New().String())
	addAttributesToSignableHeaderElement(timeStamp, timeStampId, uri_soap_12)

	cr := time.Now()
	created := timeStamp.CreateElement("wsu:Created")
	created.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", cr.Year(), cr.Month(), cr.Day(), cr.Hour(), cr.Minute(), cr.Second()))
	ex := cr.Add(time.Minute * 5)
	expires := timeStamp.CreateElement("wsu:Expires")
	expires.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", ex.Year(), ex.Month(), ex.Day(), ex.Hour(), ex.Minute(), ex.Second()))

	keyInfoDecorator := func(keyInfo *etree.Element) {
		secTokenRef := keyInfo.CreateElement("wsse:SecurityTokenReference")
		reference := secTokenRef.CreateElement("wsse:Reference")
		reference.CreateAttr("URI", fmt.Sprintf("#%s", binarySecurityTokenId))
		reference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	}

	body := envelope.CreateElement("soap:Body")
	bodyId := fmt.Sprintf("_%s", uuid.New().String())
	body.CreateAttr(namespace_adr, uri_adr)
	body.CreateAttr(namespace_ds, uri_ds)
	body.CreateAttr(namespace_saml2, uri_saml2)
	body.CreateAttr(namespace_soap, uri_soap_12)
	body.CreateAttr(namespace_wsse, uri_wsse)
	body.CreateAttr(namespace_wst14, uri_wst14)
	body.CreateAttr(namespace_wsu, uri_wsu)
	body.CreateAttr(id_attr, bodyId)

	requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
	requestSecurityToken.CreateAttr(namespace_wst, uri_wst)
	tokenType := requestSecurityToken.CreateElement("wst:TokenType")
	tokenType.SetText("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")

	requestType := requestSecurityToken.CreateElement("wst:RequestType")
	requestType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue")


	if (len(appliesToAddress) != 0) {
		appliesTo := requestSecurityToken.CreateElement("wsp:AppliesTo")
		appliesTo.CreateAttr(namespace_wsp, uri_wsp_12)
		endpointRef := appliesTo.CreateElement("adr:EndpointReference")
		endpointRef.CreateAttr(namespace_adr, uri_adr)
		address := endpointRef.CreateElement("adr:Address")
		address.SetText(appliesToAddress)
	}

	if (len(claims) != 0) {

		claimsElement := requestSecurityToken.CreateElement("wst:Claims")
		claimsElement.CreateAttr("Dialect", factory.claimDialect)
		claimsElement.CreateAttr(namespace_wsfed, uri_wsfed)

		for claimName, claimValue := range claims {

			claimValueElement := claimsElement.CreateElement("wsfed:ClaimType")
			claimValueElement.CreateAttr("Uri", claimName)
			value := claimValueElement.CreateElement("wsfed:Value")
			value.SetText(claimValue)
		}
	}


	keyType := requestSecurityToken.CreateElement("wst:KeyType")
	keyType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey")

	useKey := requestSecurityToken.CreateElement("wst:UseKey")



	binarySecurityTokenInUseKey := useKey.CreateElement("wsse:BinarySecurityToken")
	binarySecurityTokenInUseKey.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	binarySecurityTokenInUseKey.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	binarySecurityTokenInUseKey.SetText("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")


	if (delegation != nil) {
		delegationResult = requestSecurityToken.CreateElement(delegation.DelegationTagName)
		delegationResult.AddChild(delegation.CopyElement())
	}
	return doc, security, body, []*etree.Element{ action, messageId, to, replyTo, timeStamp, binarySecurityToken }, delegationResult, keyInfoDecorator
}

func (factory StsRequestFactory) signSoapRequest(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element, keyInfoDecorator func(*etree.Element), hash crypto.Hash) (*etree.Document, error) {

	ctx := &dsig.SigningContext{
		Hash:          hash,
		KeyStore:      factory.keyStore,
		IdAttribute:   id_attr,
		Prefix:        dsig.DefaultPrefix,
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	signature, err := ctx.ConstructSignatureRef(append(headersToSign, body), keyInfoDecorator, false)
	if (err != nil) {
		return nil, err
	}

	security.AddChild(signature)

	return document, err
}
