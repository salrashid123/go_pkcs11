package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/miekg/pkcs11"
	pkcs11uri "github.com/stefanberger/go-pkcs11uri"
)

const (
// export SOFTHSM2_CONF=/path/to/softhsm.conf
// export PKCS11_URI="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;slot-id=883411894;serial=71bc89cdb4a7cbb6;token=token1;object=keylabel1;id=4142?pin-value=mynewpin&module-path=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
)

func main() {
	if len(os.Args) < 2 {
		panic("Missing pkcs11 URI argument")
	}
	uristr := os.Args[1]

	uri := pkcs11uri.New()

	err := uri.Parse(uristr)
	if err != nil {
		panic(err)
	}

	//uri.SetAllowedModulePaths([]string{"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"})
	uri.SetAllowAnyModule(true)
	module, err := uri.GetModule()
	if err != nil {
		panic(err)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		panic(err)
	}

	p := pkcs11.New(module)
	err = p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slot, ok := uri.GetPathAttribute("slot-id", false)
	if !ok {
		panic("No slot-id in pkcs11 URI")
	}
	slotid, err := strconv.Atoi(slot)
	if err != nil {
		panic(err)
	}
	fmt.Printf("slot-id %d\n", slotid)

	token, ok := uri.GetPathAttribute("token", false)
	if !ok {
		panic("No slot-id in pkcs11 URI")
	}
	fmt.Printf("Token %s\n", token)

	id, ok := uri.GetPathAttribute("id", false)
	if !ok {
		panic("No slot-id in pkcs11 URI")
	}
	fmt.Printf("id %s\n", id)

	hex_id, err := hex.DecodeString(id)
	if err != nil {
		panic(err)
	}

	object, ok := uri.GetPathAttribute("object", false)
	if !ok {
		panic("No slot-id in pkcs11 URI")
	}
	fmt.Printf("Object %s\n", object)

	session, err := p.OpenSession(uint(slotid), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, object),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hex_id),
	}

	if err := p.FindObjectsInit(session, publicKeyTemplate); err != nil {
		panic(err)
	}
	ik, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	pr, err := p.GetAttributeValue(session, ik[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		panic(err)
	}

	modulus := new(big.Int)
	modulus.SetBytes(pr[0].Value)
	bigExponent := new(big.Int)
	bigExponent.SetBytes(pr[1].Value)
	exponent := int(bigExponent.Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	fmt.Printf("  Public Key: \n%s\n", pubkeyPem)

	/// *************************** Sign and verify

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, object),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hex_id),
	}

	if err := p.FindObjectsInit(session, privateKeyTemplate); err != nil {
		panic(err)
	}
	pk, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, pk[0])
	if err != nil {
		panic(err)
	}

	msg := "foo"
	sig, err := p.Sign(session, []byte(msg))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature %s\n", base64.RawStdEncoding.EncodeToString(sig))

	digest := sha256.Sum256([]byte(msg))

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Println("Signature Verified")
}
