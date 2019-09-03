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


func createIssueRequest(keyInfoElement *etree.Element) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element) {

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	envelope := doc.CreateElement("soap:Envelope")
	envelope.CreateAttr("xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope")

		header := envelope.CreateElement("soap:Header")

			action := header.CreateElement("adr:Action")
			actionId := "_2451b4b1-38d6-4395-9a28-372560725c59" //TODO generer
			action.CreateAttr("xmlns:adr", "http://www.w3.org/2005/08/addressing")
			action.CreateAttr(namespace_wsu, uri_wsu)
			action.CreateAttr(id_attr, actionId)
			action.SetText("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")

			security := header.CreateElement("wsse:Security")
			security.CreateAttr(namespace_wsse, uri_wsse)
			//security.CreateAttr(namespace_wsu, uri_wsu)
			security.CreateAttr("soap:mustUnderstand", "1")

		body := envelope.CreateElement("soap:Body")
//		body.CreateAttr(namespace_ds, uri_ds)
//		body.CreateAttr(namespace_wst, uri_wst)
		body.CreateAttr(namespace_wsu, uri_wsu)

		bodyActionId := "_a7dd77e4-586d-47b5-9b83-2ed20ff0441" // TODO generer
		body.CreateAttr(id_attr, bodyActionId)

			requestSecurityToken := body.CreateElement("wst:RequestSecurityToken")
			requestSecurityToken.CreateAttr(namespace_ds, uri_ds)
			requestSecurityToken.CreateAttr(namespace_wst, uri_wst)

				useKey := requestSecurityToken.CreateElement("wst:UseKey")

				useKey.AddChild(keyInfoElement)

	return doc, security, body, []*etree.Element{ action }
}


func (factory StsRequestFactory) signSoapRequest2(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) (*etree.Document, error) {
        ctx := dsig.NewDefaultSigningContext(factory.keyStore)
        contents, _ := ctx.Canonicalizer.Canonicalize(document.Root())

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(contents); err != nil {
		    	panic(err)
	}

	bodyPath, err := etree.CompilePath("/soap:Envelope/soap:Body")
	body = doc.FindElementPath(bodyPath)
	if (body == nil) {
                panic("body element not found")
        }


	securityPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security")
        security = doc.FindElementPath(securityPath)
        if (security == nil) {
                panic("security element not found")
        }


        // Start by signing the body and creating the Signature element under the Security node of the request
        signedBody, err := ctx.ConstructSignature([]*etree.Element { body }, false)
        if (err != nil) {
                return nil, err
        }

        security.AddChild(signedBody)

        signedInfoPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security/ds:Signature/ds:SignedInfo")
        signedInfoElement := doc.FindElementPath(signedInfoPath)
        if (signedInfoElement == nil) {
                panic("element not found")
        }


	return doc, nil
        // Append each of the Request elements containing the header digests to the Signature element
        for _, header := range headersToSign {

                signedHeader, _ := ctx.ConstructSignature([]*etree.Element { header }, false)
                doc := etree.NewDocument()
                doc.SetRoot(signedHeader)

                referencePath, _ := etree.CompilePath("./ds:Signature/ds:SignedInfo/ds:Reference")
                referenceElement := doc.FindElementPath(referencePath)
                if (referenceElement == nil) {
                        panic("element not found2")
                }

                signedInfoElement.AddChild(referenceElement)
        }
/*
        // TODO: Create the signature based on all of the digests*/
        return doc, nil
}




func (factory StsRequestFactory) signSoapRequest(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element) (*etree.Document, error) {

        ctx := dsig.NewDefaultSigningContext(factory.keyStore)

        // Start by signing the body and creating the Signature element under the Security node of the request
        signedBody, err := ctx.ConstructSignature([]*etree.Element { body }, false)
	if (err != nil) {
		return nil, err
	}
        security.AddChild(signedBody)

        signedInfoPath, err := etree.CompilePath("/soap:Envelope/soap:Header/wsse:Security/ds:Signature/ds:SignedInfo")
        signedInfoElement := document.FindElementPath(signedInfoPath)
        if (signedInfoElement == nil) {
                panic("element not found")
        }

        // Append each of the Request elements containing the header digests to the Signature element
/*        for _, header := range headersToSign {

                signedHeader, _ := ctx.ConstructSignature(header, false)
                doc := etree.NewDocument()
                doc.SetRoot(signedHeader)

                referencePath, _ := etree.CompilePath("./ds:Signature/ds:SignedInfo/ds:Reference")
                referenceElement := doc.FindElementPath(referencePath)
                if (referenceElement == nil) {
                        panic("element not found2")
                }

                signedInfoElement.AddChild(referenceElement)
        }*/

        // TODO: Create the signature based on all of the digests
	return document, nil
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

        contents, _ := ctx.Canonicalizer.Canonicalize(document.Root())
        doc := etree.NewDocument()
        if err := doc.ReadFromBytes(contents); err != nil {
                panic(err)
        }

	bodyPath, err := etree.CompilePath("./soap:Envelope/soap:Body")
	if (err != nil) {
		panic(err)
	}
        bodyElement := doc.FindElementPath(bodyPath)

	actionPath, err := etree.CompilePath("./soap:Envelope/soap:Header/Action")
	if (err != nil) {
		panic(err)
	}
	actionElement := doc.FindElementPath(actionPath)

	sig, err := ctx.ConstructSignature([]*etree.Element { bodyElement, actionElement }, false)
	if (err != nil) {
		panic(err)
	}

//        ret := bodyElement.Copy()
	ret := document.Root().Copy()
	//ret.Child = append(ret.Child, sig)
	docNew := etree.NewDocument()
	docNew.SetRoot(ret)
//	docNew.Root = ret;

//	return docNew, nil

        securityPath, err := etree.CompilePath("./soap:Envelope/soap:Header/wsse:Security")
        securityElement := docNew.FindElementPath(securityPath)

	securityElement.AddChild(sig)

	return docNew, err
}

