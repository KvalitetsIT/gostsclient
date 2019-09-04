package stsclient

import (
	"testing"
	"crypto"
	"crypto/tls"
//	"encoding/pem"
//        "github.com/russellhaering/gosaml2/types"

//	"fmt"
 	"gotest.tools/assert"
  	dsig "github.com/russellhaering/goxmldsig"
	etree "github.com/beevik/etree"

//	"io/ioutil"
)

func TestGetStsRequestNoSignature(t *testing.T) {

	// Given
	clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
	keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore)


	// When
	request, err := subject.CreateStsRequest(false)

	// Given
//	clientCert, err := ioutil.ReadFile("./testdata/client.crt")
//	block, _ := pem.Decode([]byte(clientCert))
//	cert, err := x509.ParseCertificate(block.Bytes)
//	context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
 //       	Roots: []*x509.Certificate { cert },
 //   	})

   /*     subject := NewTokenAuthenticator(context)
	bs, err := ioutil.ReadFile("./testdata/authenticate_body_first")

	// When
	assertion, errProcess := subject.ParseAndValidateAuthenticationRequestPayload(bs) 
*/
	// Then
	s, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "couldn't read testdata authenticate_body_first")
	assert.Equal(t, "1.0", s)
//	assert.Equal(t, assertion.Version, "2.0")
//	assert.Equal(t, len(assertion.AttributeStatement.Attributes), 4)
	// TODO: tjek flere
}

func TestGetStsRequestSigned(t *testing.T) {

        // Given
        clientKeyPair, _ := tls.LoadX509KeyPair("./testdata/medcom.cer", "./testdata/medcom.pem")
        keyStore := dsig.TLSCertKeyStore(clientKeyPair)
        subject, _ := NewStsRequestFactory(keyStore)

        // When
        request, err := subject.CreateStsRequest(true)


	// Then
	s, _ := request.SoapEnvelope.WriteToString()
	assert.NilError(t, err, "Error creating request")
	assert.Equal(t, "1.0", s)

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

	signed, _ := ctx.ConstructSignature([]*etree.Element { body }, false)
	header.AddChild(signed)

        //str, _  := doc.WriteToString()
	//assert.Equal(t, "1.0", str)
}
