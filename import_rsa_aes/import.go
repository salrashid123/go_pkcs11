package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
)

const (
	pin = "mynewpin"
)

var ()

func main() {

	// Init PKCS

	p := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	err := p.Initialize()
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

	//   1.  Create AES key, test encryption and decryption

	// first lookup the key
	buf := new(bytes.Buffer)
	var num uint16 = 1
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	id := buf.Bytes()

	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we don't need to extract this..
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "WrappingAESKey"), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	aesKey, err := p.CreateObject(session, aesKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
	}

	log.Printf("Created AES Key: %v", aesKey)

	ktemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "WrappingAESKey"),
	}
	if err := p.FindObjectsInit(session, ktemplate); err != nil {
		panic(err)
	}
	kobjs, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	iv := make([]byte, 16)
	_, err = rand.Read(iv)

	if err != nil {
		panic(err)
	}

	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, kobjs[0])
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	ct, err := p.Encrypt(session, []byte("foo"))
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	// append the IV to the ciphertext
	cdWithIV := append(iv, ct...)

	log.Printf("Encrypted IV+Ciphertext %s", base64.RawStdEncoding.EncodeToString(cdWithIV))

	aesKey = kobjs[0]

	err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, cdWithIV[0:16])}, aesKey)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	pt, err := p.Decrypt(session, ct[:16])
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("Decrypt %s", string(pt))

	/// 3 Create Public/Private Key to transfer back using wrapping key
	//   Note the following would happen on the remote HSM that would have loaded the wrapping public key

	buf = new(bytes.Buffer)
	num = 4
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	pubID := buf.Bytes()

	buf = new(bytes.Buffer)
	num = 5
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	privID := buf.Bytes()

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, privID),
	}

	pbk, pvk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatalf("failed to generate exportable keypair: %s\n", err)
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
	modulus.SetBytes(pr[0].Value)
	bigExponent := new(big.Int)
	bigExponent.SetBytes(pr[1].Value)
	exponent := int(bigExponent.Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	log.Printf("  Public Key: \n%s\n", pubkeyPem)

	msg := []byte("foo")
	fmt.Printf("Signing %d bytes with %s\n", len(msg), msg)
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, pvk)
	if err != nil {
		log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
	}

	// Sign 'msg'
	sig, err := p.Sign(session, msg)
	if err != nil {
		err = fmt.Errorf("Signing failed (%s)\n", err.Error())
		return
	}

	log.Printf("Signature %s", base64.RawStdEncoding.EncodeToString(sig))

	digest := sha256.Sum256(msg)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig)
	if err != nil {
		log.Printf("Failed verification. Retrying: %s", err)
		return
	}

	log.Printf(">>>>>> Signature Verified")

	//  4.  Now wrap the new key with the wrapping public key

	// A) wrap RSA private key using AES wrapping key
	wrappedPrivBytes, err := p.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, pvk)

	if err != nil {
		log.Fatalf("failed to wrap privatekey : %s\n", err)
	}
	//log.Printf("%v, %v", wrappedPubBytes, wrappedPrivBytes)

	buf = new(bytes.Buffer)
	num = 6
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	importedPrivID := buf.Bytes()

	importedPrivateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "UnwrappedRSAKey"),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, importedPrivID),
	}
	aesKeyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "My Second AES Key"), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, importedPrivID),
	}

	// A) unwrap RSA private key using AES key
	ik, err := p.UnwrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, wrappedPrivBytes, importedPrivateKeyTemplate)

	if err != nil {
		log.Fatalf("Unwrap Failed: %v", err)
	}

	fmt.Printf("Signing %d bytes with %s\n", len(msg), msg)
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, ik)
	if err != nil {
		log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
	}

	// Sign 'msg'
	sig, err = p.Sign(session, msg)
	if err != nil {
		err = fmt.Errorf("signing failed (%s)\n", err.Error())
		return
	}

	log.Printf("Signature %s", base64.RawStdEncoding.EncodeToString(sig))

}
