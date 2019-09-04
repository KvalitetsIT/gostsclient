package stsclient

import (
	etree "github.com/beevik/etree"
	"crypto"
	"fmt"
	"time"
	dsig "github.com/russellhaering/goxmldsig"
	uuid "github.com/google/uuid"
)

const id_attr			= "wsu:Id"
const namespace_adr		= "xmlns:adr"
const namespace_ds		= "xmlns:ds"
const namespace_soap		= "xmlns:soap"
const namespace_wsu		= "xmlns:wsu"
const namespace_wst		= "xmlns:wst"
const namespace_wsse		= "xmlns:wsse"
const namespace_wsp		= "xmlns:wsp"
const uri_adr			= "http://www.w3.org/2005/08/addressing"
const uri_ds			= "http://www.w3.org/2000/09/xmldsig#"
const uri_soap			= "http://schemas.xmlsoap.org/soap/envelope/"
const uri_wsu 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const uri_wst			= "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const uri_wsse			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
const uri_wsp			= "http://www.w3.org/ns/ws-policy"

type StsRequest struct {

	SoapEnvelope		*etree.Document
}

type StsRequestFactory struct {

	keyInfoElement		*etree.Element
	keyStore		dsig.TLSCertKeyStore

	stsUrl			string
	appliesToAddress	string
}

func NewStsRequestFactory(keyStore dsig.TLSCertKeyStore) (*StsRequestFactory, error) {

	keyInfoElement, err := getKeyInfoElementFromKeyStore(keyStore)
	if (err != nil) {
		return nil, err
	}

	stsRequestFactory := StsRequestFactory{ keyInfoElement: keyInfoElement, keyStore: keyStore, stsUrl: "https://sts.test-vdxapi.vconf.dk/sts/service/sts", appliesToAddress: "urn:medcom:videoapi" }

	return &stsRequestFactory, nil
}

func getKeyInfoElementFromKeyStore(keyStore dsig.TLSCertKeyStore) (*etree.Element, error) {

	ctx := dsig.NewDefaultSigningContext(keyStore)

	doc := etree.NewDocument()
        doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
        root := doc.CreateElement("Root")
	root.CreateAttr("ID", "dummy")

	signed, err := ctx.SignEnveloped(root)
      	if (err != nil) {
		return nil, err
        }
	doc.SetRoot(signed)

	keyInfoPath, err := etree.CompilePath("./Root/ds:Signature/ds:KeyInfo")
	if (err != nil) {
                return nil, err
        }

	keyInfo := doc.FindElementPath(keyInfoPath)
	if (keyInfo == nil) {
		panic("Keyinfo not found")
	}
	docResult := etree.NewDocument()
	docResult.SetRoot(keyInfo)

	return keyInfo, nil
}


func (factory *StsRequestFactory) CreateStsRequest(sign bool) (*StsRequest, error) {

	soapEnvelope, securityElement, soapBody, headersToSign := createIssueRequest(factory.keyInfoElement, factory.stsUrl, factory.appliesToAddress)

	if (sign) {
		signedEnvelope, err := factory.signSoapRequest3(soapEnvelope, securityElement, soapBody, headersToSign)
		if (err != nil) {
			return nil, err
		}
		soapEnvelope = signedEnvelope
	}

	stsRequest := StsRequest{ SoapEnvelope: soapEnvelope }
	return &stsRequest, nil
}

func addAttributesToSignableHeaderElement(headerElement *etree.Element, id string) {

	headerElement.CreateAttr(namespace_adr, uri_adr)
        headerElement.CreateAttr(namespace_ds, uri_ds)
        headerElement.CreateAttr(namespace_soap, uri_soap)
        headerElement.CreateAttr(namespace_wsse, uri_wsse)
        headerElement.CreateAttr(namespace_wsu, uri_wsu)
        headerElement.CreateAttr(id_attr, id)
}

// Det virker somom, at signeringen er meget følsom overfor namespace definitioner (noget med canonization), hvis du laver om i nedenstående, så test, at output kan
// verificeres på https://tools.chilkat.io/xmlDsigVerify.cshtml (ret tests til, så du får output)
func createIssueRequest(keyInfoElement *etree.Element, stsUrl string, appliesToAddress string) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element) {

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr(namespace_adr, uri_adr)
        envelope.CreateAttr(namespace_ds, uri_ds)
	envelope.CreateAttr(namespace_soap, uri_soap)
        envelope.CreateAttr(namespace_wsse, uri_wsse)
        envelope.CreateAttr(namespace_wsu, uri_wsu)

		header := envelope.CreateElement("soap:Header")
		header.CreateAttr(namespace_soap, uri_soap)

			action := header.CreateElement("adr:Action")
			action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
			actionId := fmt.Sprintf("_%s", uuid.New().String())
			addAttributesToSignableHeaderElement(action, actionId)

			messageId := header.CreateElement("adr:MessageID")
			messageId.SetText(fmt.Sprintf("urn:uuid:%s", uuid.New().String()))
			messageIdId := fmt.Sprintf("_%s", uuid.New().String())
                        addAttributesToSignableHeaderElement(messageId, messageIdId)

			to := header.CreateElement("adr:To")
			to.SetText(stsUrl)
			toId := fmt.Sprintf("_%s", uuid.New().String()) 
			addAttributesToSignableHeaderElement(to, toId)

 			replyTo := header.CreateElement("adr:ReplyTo")
				replyToAddress := replyTo.CreateElement("adr:Address")
				replyToAddress.SetText("http://www.w3.org/2005/08/addressing/anonymous")
			replyToId := fmt.Sprintf("_%s", uuid.New().String()) 
			addAttributesToSignableHeaderElement(replyTo, replyToId)

			security := header.CreateElement("wsse:Security")
			security.CreateAttr(namespace_ds, uri_ds)
                        security.CreateAttr(namespace_wsse, uri_wsse)
			security.CreateAttr(namespace_wsu, uri_wsu)
                        security.CreateAttr("soap:mustUnderstand", "1")

				timeStamp := security.CreateElement("wsu:Timestamp")
				timeStampId := fmt.Sprintf("_%s", uuid.New().String())
				timeStamp.CreateAttr(id_attr, timeStampId)
					loc, _ := time.LoadLocation("Europe/Copenhagen")
					cr := time.Now().In(loc)
					created := timeStamp.CreateElement("wsu:Created")
					created.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", cr.Year(), cr.Month(), cr.Day(), cr.Hour(), cr.Minute(), cr.Second()))
					ex := cr.Add(time.Minute * 5)
					expires := timeStamp.CreateElement("wsu:Expires")
					expires.SetText(fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.000Z", ex.Year(), ex.Month(), ex.Day(), ex.Hour(), ex.Minute(), ex.Second()))

		body := envelope.CreateElement("soap:Body")
		bodyActionId := fmt.Sprintf("_%s", uuid.New().String())
		body.CreateAttr(namespace_adr, uri_adr)
		body.CreateAttr(namespace_ds, uri_ds)
        	body.CreateAttr(namespace_soap, uri_soap)
        	body.CreateAttr(namespace_wsse, uri_wsse)
        	body.CreateAttr(namespace_wsu, uri_wsu)
		body.CreateAttr(id_attr, bodyActionId)

			requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
			requestSecurityToken.CreateAttr(namespace_wst, uri_wst)

				requestType := requestSecurityToken.CreateElement("wst:RequestType")
				requestType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue")

				appliesTo := requestSecurityToken.CreateElement("wsp:AppliesTo")
				appliesTo.CreateAttr(namespace_wsp, uri_wsp)
					endpointRef := appliesTo.CreateElement("adr:EndpointReference")
					endpointRef.CreateAttr(namespace_adr, uri_adr)
						address := endpointRef.CreateElement("adr:Address")
						address.SetText(appliesToAddress)

				tokenType := requestSecurityToken.CreateElement("wst:TokenType")
				tokenType.SetText("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")

				keyType := requestSecurityToken.CreateElement("wst:KeyType")
				keyType.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey")

				useKey := requestSecurityToken.CreateElement("wst:UseKey")
				useKey.CreateAttr(namespace_ds, uri_ds)

				useKey.AddChild(keyInfoElement)

	return doc, security, body, []*etree.Element{ action, messageId, to, replyTo }
}

func (factory StsRequestFactory) signSoapRequest3(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) (*etree.Document, error) {

        ctx := &dsig.SigningContext{
                Hash:          crypto.SHA256,
                KeyStore:      factory.keyStore,
                IdAttribute:   id_attr,
                Prefix:        dsig.DefaultPrefix,
                Canonicalizer: dsig.MakeC14N11Canonicalizer(),
        }

	signature, err := ctx.ConstructSignature(append(headersToSign, body), false)
	if (err != nil) {
		return nil, err
	}

	security.AddChild(signature)

	return document, err
}
