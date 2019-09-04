package stsclient

import (
	etree "github.com/beevik/etree"
	"crypto"
	dsig "github.com/russellhaering/goxmldsig"
)

const id_attr			= "wsu:Id"
const namespace_ds		= "xmlns:ds"
const namespace_wsu		= "xmlns:wsu"
const namespace_wst		= "xmlns:wst"
const namespace_wsse		= "xmlns:wsse"
const uri_ds			= "http://www.w3.org/2000/09/xmldsig#"
const uri_wsu 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const uri_wst			= "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const uri_wsse			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

type StsRequest struct {

	SoapEnvelope		*etree.Document
}

type StsRequestFactory struct {

	keyInfoElement		*etree.Element
	keyStore		dsig.TLSCertKeyStore
}

func NewStsRequestFactory(keyStore dsig.TLSCertKeyStore) (*StsRequestFactory, error) {

	keyInfoElement, err := getKeyInfoElementFromKeyStore(keyStore)
	if (err != nil) {
		return nil, err
	}

	stsRequestFactory := StsRequestFactory{ keyInfoElement: keyInfoElement, keyStore: keyStore }

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
		// TODO lav error
		panic("keyinfo not found")
	}
	docResult := etree.NewDocument()
	docResult.SetRoot(keyInfo)

	return keyInfo, nil
}


func (factory *StsRequestFactory) CreateStsRequest(sign bool) (*StsRequest, error) {

	soapEnvelope, securityElement, soapBody, headersToSign := createIssueRequest(factory.keyInfoElement)

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
	headerElement.CreateAttr("xmlns:adr", "http://www.w3.org/2005/08/addressing")
        headerElement.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")
        headerElement.CreateAttr(namespace_wsu, uri_wsu)
        headerElement.CreateAttr(id_attr, id)
}


func createIssueRequest(keyInfoElement *etree.Element) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element) {

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")

		header := envelope.CreateElement("soap:Header")
		header.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")

			action := header.CreateElement("adr:Action")
			action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
			actionId := "_2451b4b1-38d6-4395-9a28-372560725c59" //TODO generer
			addAttributesToSignableHeaderElement(action, actionId)

 			replyTo := header.CreateElement("adr:ReplyTo")
				replyToAddress := replyTo.CreateElement("adr:Address")
				replyToAddress.SetText("http://www.w3.org/2005/08/addressing/anonymous")
			replyToId := "_1231b4b1-38d6-4395-9a28-372560725cee" //TODO generer
			addAttributesToSignableHeaderElement(replyTo, replyToId)

			security := header.CreateElement("wsse:Security")
			security.CreateAttr(namespace_ds, uri_ds)
                        security.CreateAttr(namespace_wsse, uri_wsse)
			security.CreateAttr(namespace_wsu, uri_wsu)
                        security.CreateAttr("soap:mustUnderstand", "1")


		body := envelope.CreateElement("soap:Body")
		bodyActionId := "_a7dd77e4-586d-47b5-9b83-2ed20ff0441" // TODO generer
		body.CreateAttr(namespace_wsu, uri_wsu)
		body.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")
		body.CreateAttr(id_attr, bodyActionId)

			requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
			requestSecurityToken.CreateAttr(namespace_wst, uri_wst)

				useKey := requestSecurityToken.CreateElement("wst:UseKey")
				useKey.CreateAttr(namespace_ds, uri_ds)

				useKey.AddChild(keyInfoElement)

	return doc, security, body, []*etree.Element{ action, replyTo }
}

func (factory StsRequestFactory) signSoapRequest3(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) (*etree.Document, error) {

//        ctx := dsig.NewDefaultSigningContext(factory.keyStore)
        ctx := &dsig.SigningContext{
                Hash:          crypto.SHA256,
                KeyStore:      factory.keyStore,
                IdAttribute:   id_attr,//"wsu:Id",
                Prefix:        dsig.DefaultPrefix,
                Canonicalizer: dsig.MakeC14N11Canonicalizer(),
        }

  /*      contents, _ := ctx.Canonicalizer.Canonicalize(body)
        doc := etree.NewDocument()
        if err := doc.ReadFromBytes(contents); err != nil {
                panic(err)
        }
	return doc, nil
*/

/*	bodyPath, err := etree.CompilePath("./soap:Envelope/soap:Body")
	if (err != nil) {
		panic(err)
	}
        bodyElement := doc.FindElementPath(bodyPath)*/

//	actionPath, err := etree.CompilePath("./soap:Envelope/soap:Header/Action")
//	if (err != nil) {
//		panic(err)
//	}
//	actionElement := doc.FindElementPath(actionPath)

	sig, err := ctx.ConstructSignature(append(headersToSign, body), false)
	if (err != nil) {
		panic(err)
	}

	security.AddChild(sig)

	return document, err
}

