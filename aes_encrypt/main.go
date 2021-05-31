package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"

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
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we don't need to extract this..
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKey"),         /* Name of Key */
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
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKey"),
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

}
