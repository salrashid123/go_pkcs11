package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
)

const (
	pin = "mynewpin"
)

var ()

func main() {

	// Read public, private keys
	// extract the modulus, exponent, primes

	priv, err := ioutil.ReadFile("priv.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(priv)

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic(err)
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic(err)
	}

	pub, err := ioutil.ReadFile("pub.pem")
	if err != nil {
		panic(err)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		log.Fatal("key is null")
	}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		panic(err)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		panic(err)
	}

	log.Printf("Public Key Modulus %v", pubKey.N)
	log.Printf("Private Key Modulus %v", privateKey.PublicKey.N)
	// Init PKCS

	p := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	err = p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

	fmt.Println()

	buf := new(bytes.Buffer)
	var num uint16 = 1
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	pubID := buf.Bytes()

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, privateKey.PublicKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),

		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),

		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, privateKey.PublicKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, big.NewInt(int64(privateKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, new(big.Int).Set(privateKey.Primes[0]).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, new(big.Int).Set(privateKey.Primes[1]).Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, new(big.Int).Set(privateKey.Precomputed.Dp).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, new(big.Int).Set(privateKey.Precomputed.Dq).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, new(big.Int).Set(privateKey.Precomputed.Qinv).Bytes()),
	}

	pbk, err := p.CreateObject(session, publicKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GeneratePublicKey() failed %s\n", err))
	}

	pvk, err := p.CreateObject(session, privateKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GeneratePrivateKey() failed %s\n", err))
	}

	// Create a test signature and verify with keypair

	pr, err := p.GetAttributeValue(session, pbk, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		panic(err)
	}

	modulus := new(big.Int)
	bigExponent := new(big.Int)
	exponent := int(bigExponent.SetBytes(pr[1].Value).Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus.SetBytes(pr[0].Value),
		E: exponent,
	}

	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	log.Printf("  Public Key: \n%s\n", pubkeyPem)

	// ********************

	msg := []byte("foo")
	fmt.Printf("Signing %d bytes with %s\n", len(msg), msg)
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, pvk)
	if err != nil {
		log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
	}

	// Sign 'msg'
	sig, err := p.Sign(session, msg)
	if err != nil {
		panic(err)
	}

	log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

	hasher := sha256.New()
	hasher.Write(msg)

	/// use rsaPub as derived from exponent, modulus
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hasher.Sum(nil), sig)
	if err != nil {
		panic(err)
	}

	log.Printf(">>>>>> Signature Verified")

	// use pubKey as read from pub.pem

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hasher.Sum(nil), sig)
	if err != nil {
		panic(err)
	}

	log.Printf(">>>>>> Signature Verified")

	// verify with loaded Key

	err = p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, pbk)
	if err != nil {
		panic(err)
	}

	err = p.Verify(session, msg, sig)
	if err != nil {
		panic(err)
	}

	log.Printf(">>>>>> Signature Verified")

}
