package stsclient

import (
	etree "github.com/beevik/etree"
	"crypto"
	"fmt"
	"time"
	"encoding/base64"
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

func NewStsRequestFactory(keyStore dsig.TLSCertKeyStore, stsUrl string) (*StsRequestFactory, error) {

	keyInfoElement, err := getKeyInfoElementFromKeyStore(keyStore)
	if (err != nil) {
		return nil, err
	}

	stsRequestFactory := StsRequestFactory{ keyInfoElement: keyInfoElement, keyStore: keyStore, stsUrl: stsUrl, appliesToAddress: "urn:kit:testa:servicea" }

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

	_, cert, err := factory.keyStore.GetKeyPair()
	if (err != nil) {
		return nil, err
	}

	soapEnvelope, securityElement, soapBody, headersToSign, keyInfoDecorator := createIssueRequest(factory.keyInfoElement, factory.stsUrl, factory.appliesToAddress, cert)

	if (sign) {
		signedEnvelope, err := factory.signSoapRequest3(soapEnvelope, securityElement, soapBody, headersToSign, keyInfoDecorator)
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
func createIssueRequest(keyInfoElement *etree.Element, stsUrl string, appliesToAddress string, cert []byte) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element, func(*etree.Element)) {

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
				timeStampId := fmt.Sprintf("TS-%s", uuid.New().String())
				addAttributesToSignableHeaderElement(timeStamp, timeStampId)

					//loc, _ := time.LoadLocation("Europe/Copenhagen")
					cr := time.Now()//.Add(time.Minute * -2)
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
        	body.CreateAttr(namespace_soap, uri_soap)
        	body.CreateAttr(namespace_wsse, uri_wsse)
        	body.CreateAttr(namespace_wsu, uri_wsu)
		body.CreateAttr(id_attr, bodyId)

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

				//useKey.AddChild(keyInfoElement)

				keyInfoE := useKey.CreateElement("ds:KeyInfo")
				keyInfoE.CreateAttr(namespace_ds, uri_ds)

					keyValue := keyInfoE.CreateElement("ds:KeyValue")

						rsaKeyValue := keyValue.CreateElement("ds:RSAKeyValue")

							modulus := rsaKeyValue.CreateElement("ds:Modulus")
							modulus.SetText("rXApxxjCWlsEfeKgUPOl1mJC9aqkkWooyUgOU+KsrH9qRCoK9xVdI7YJebwr5+TJtBbWkKkuD926SMxJV1LY6IT8tCflomIl4E5IZdRZPci1N71lQDV6SfNuGPHNpFpLssdSY34+t4/vuGeTZ2lJB5IP4sDvjAxJ+nXECcHmcupEEQu3wI2nijcWl4hRRSdhUuKDB/AiaZvsPKcdFj4WTlRdewJS4v5m1khwce6Zj1jw6N7PSQPHaisIxqx2SMHvKiepPuESgEpqP+sGRaL2ESJWuB1kTsNHmer6cJ+ba/pvJy3xraY7mrgRv/zWa+6Of9LSVw2hfFx3pEjBgYHhhw==")

							exp := rsaKeyValue.CreateElement("ds:Exponent")
							exp.SetText("AQAB")
				// end

				requestSecurityToken.CreateElement("wst:Renewing")
	return doc, security, body, []*etree.Element{ action, messageId, to, replyTo, timeStamp }, keyInfoDecorator
}

func (factory StsRequestFactory) signSoapRequest3(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element, keyInfoDecorator func(*etree.Element)) (*etree.Document, error) {

        ctx := &dsig.SigningContext{
                Hash:          crypto.SHA1,
                KeyStore:      factory.keyStore,
                IdAttribute:   id_attr,
                Prefix:        dsig.DefaultPrefix,
                Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),//MakeC14N11Canonicalizer(),
        }

	signature, err := ctx.ConstructSignatureRef(append(headersToSign, body), keyInfoDecorator, false)
	if (err != nil) {
		return nil, err
	}

	security.AddChild(signature)

	return document, err
}
