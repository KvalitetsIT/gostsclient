package stsclient

import (
	"testing"
	"crypto"
	"crypto/tls"
//	"crypto/x509"
	"encoding/base64"
 	"gotest.tools/assert"
  	dsig "github.com/russellhaering/goxmldsig"
	etree "github.com/beevik/etree"
)

func TestGetStsRequestNoSignature(t *testing.T) {

	// Given
	clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore, "https://test")


	// When
	request, err := subject.CreateStsRequest("audience", nil, false)

	// Then
	soapStr, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")
	assert.Equal(t, soapStr, soapStr)
}

func TestGetStsRequestSigned(t *testing.T) {

        // Given
        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore, "https://test")

        // When
        request, err := subject.CreateStsRequest("audience", nil, true)


	// Then
	soapStr, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "Error creating request")
	assert.Equal(t, soapStr, soapStr)
}

///////////////////////////////////////////////
//
// Ikke rigtige tests, men diverse kodestumper
//
///////////////////////////////////////////////
func TestFormatCert(t *testing.T) {

        // Given
        tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")

	//clientPubBytes := x509.MarshalPKCS1PublicKey(clientKeyPair.PrivateKey.PublicKey())

	encoded := base64.StdEncoding.EncodeToString([]byte(""))

	assert.Equal(t, encoded, encoded)
}

func TestSignEnveloped(t *testing.T) {

	keyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        keyStore := dsig.TLSCertKeyStore(keyPair)

        doc := etree.NewDocument()
        doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
        envelope := doc.CreateElement("Envelope")
      	envelope.CreateElement("Header")
	body := envelope.CreateElement("Body")
	body.CreateAttr("ID", "_id9837432984298")

       	ctx := &dsig.SigningContext{
                Hash:          crypto.SHA256,
                KeyStore:      keyStore,
                IdAttribute:   "ID",
                Prefix:        dsig.DefaultPrefix,
                Canonicalizer: dsig.MakeC14N11Canonicalizer(),
        }
	signed, _ := ctx.SignEnveloped(body)

	newDoc := etree.NewDocument()
        newDoc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
        newEnvelope := newDoc.CreateElement("Envelope")
        newEnvelope.CreateElement("Header")
	newEnvelope.AddChild(signed)

	newDoc.WriteToString()
}

func TestConstructSignature(t *testing.T) {

        keyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        keyStore := dsig.TLSCertKeyStore(keyPair)

        doc := etree.NewDocument()
        doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
        envelope := doc.CreateElement("Envelope")
        header := envelope.CreateElement("Header")
        body := envelope.CreateElement("Body")
        body.CreateAttr("ID", "_id9837432984298")

        ctx := &dsig.SigningContext{
                Hash:          crypto.SHA256,
                KeyStore:      keyStore,
                IdAttribute:   "ID",
                Prefix:        dsig.DefaultPrefix,
                Canonicalizer: dsig.MakeC14N11Canonicalizer(),
        }

	signed, _ := ctx.ConstructSignature(body, false)
	header.AddChild(signed)

        str, _  := doc.WriteToString()
	assert.Equal(t, str, str)
}
