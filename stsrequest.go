package stsclient

import (
	etree "github.com/beevik/etree"
	"bytes"
	"crypto"
	"fmt"
	"time"
	"net/http"
	"encoding/base64"
	dsig "github.com/russellhaering/goxmldsig"
	uuid "github.com/google/uuid"
)

const id_attr			= "wsu:Id"

const namespace_adr		= "xmlns:adr"
const namespace_ds		= "xmlns:ds"
const namespace_ic		= "xmlns:ic"
const namespace_soap		= "xmlns:soap"
const namespace_wsu		= "xmlns:wsu"
const namespace_wst		= "xmlns:wst"
const namespace_wsse		= "xmlns:wsse"
const namespace_wsp		= "xmlns:wsp"
const uri_adr			= "http://www.w3.org/2005/08/addressing"
const uri_ds			= "http://www.w3.org/2000/09/xmldsig#"
const uri_ic			= "http://schemas.xmlsoap.org/ws/2005/05/identity"
const uri_soap			= "http://schemas.xmlsoap.org/soap/envelope/"
const uri_wsu 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const uri_wst			= "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const uri_wsse			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
const uri_wsp			= "http://www.w3.org/ns/ws-policy"

type StsRequest struct {

	SoapEnvelope		*etree.Document
}

type StsRequestFactory struct {

	keyStore		dsig.TLSCertKeyStore

	stsUrl			string
}

func NewStsRequestFactory(keyStore dsig.TLSCertKeyStore, stsUrl string) (*StsRequestFactory, error) {

	stsRequestFactory := StsRequestFactory{ keyStore: keyStore, stsUrl: stsUrl }

	return &stsRequestFactory, nil
}

func (factory *StsRequestFactory) CreateStsIssueRequest(appliesTo string, claims map[string]string) (*http.Request, error) {
        stsRequest, err := factory.CreateStsRequest(appliesTo, claims, true)
        if (err != nil) {
                return nil, err
        }

        soapStr, err := stsRequest.SoapEnvelope.WriteToString()
        if (err != nil) {
                return nil, err
        }

        issueRequest, err := http.NewRequest("POST", factory.stsUrl, bytes.NewBuffer([]byte(soapStr)))
        issueRequest.Header.Set("SOAPAction", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")

	return issueRequest, nil
}

func (factory *StsRequestFactory) CreateStsRequest(appliesTo string, claims map[string]string, sign bool) (*StsRequest, error) {

	soapEnvelope, securityElement, soapBody, headersToSign, keyInfoDecorator := factory.createIssueRequest(appliesTo, claims)

	if (sign) {
		signedEnvelope, err := factory.signSoapRequest(soapEnvelope, securityElement, soapBody, headersToSign, keyInfoDecorator)
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
func (factory *StsRequestFactory) createIssueRequest(appliesToAddress string, claims map[string]string) (*etree.Document, *etree.Element, *etree.Element, []*etree.Element, func(*etree.Element)) {

        _, cert, err := factory.keyStore.GetKeyPair()
        if (err != nil) {
                panic(err)
        }

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
			to.SetText(factory.stsUrl)
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

						x509Data := keyInfo.CreateElement("ds:X509Data")

							x509Certificate := x509Data.CreateElement("ds:X509Certificate")
							x509Certificate.SetText(binarySecurityTokenValue)

				requestSecurityToken.CreateElement("wst:Renewing")
	return doc, security, body, []*etree.Element{ action, messageId, to, replyTo, timeStamp }, keyInfoDecorator
}

func (factory StsRequestFactory) signSoapRequest(document *etree.Document, security *etree.Element, body *etree.Element, headersToSign []*etree.Element, keyInfoDecorator func(*etree.Element)) (*etree.Document, error) {

        ctx := &dsig.SigningContext{
                Hash:          crypto.SHA1,
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
