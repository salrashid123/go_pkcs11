package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

const (
	pin = "mynewpin"
)

var ()

// **************** START COPY

// taken from https://github.com/ThalesGroup/crypto11/blob/master/ecdsa.go
type curveInfo struct {
	// ASN.1 marshaled OID
	oid []byte

	// Curve definition in Go form
	curve elliptic.Curve
}

var wellKnownCurves = map[string]curveInfo{
	"P-192": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}),
		nil,
	},
	"P-224": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}),
		elliptic.P224(),
	},
	"P-256": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		elliptic.P256(),
	},
	"P-384": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
		elliptic.P384(),
	},
	"P-521": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
		elliptic.P521(),
	},

	"K-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 1}),
		nil,
	},
	"K-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 26}),
		nil,
	},
	"K-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 16}),
		nil,
	},
	"K-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 36}),
		nil,
	},
	"K-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 38}),
		nil,
	},

	"B-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 15}),
		nil,
	},
	"B-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 27}),
		nil,
	},
	"B-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 17}),
		nil,
	},
	"B-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 37}),
		nil,
	},
	"B-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 39}),
		nil,
	},
}

func marshalEcParams(c elliptic.Curve) ([]byte, error) {
	if ci, ok := wellKnownCurves[c.Params().Name]; ok {
		return ci.oid, nil
	}
	// TODO use ANSI X9.62 ECParameters representation instead
	return nil, errors.New("Unknown EC")
}

// ASN.1 marshal some value and panic on error
func mustMarshal(val interface{}) []byte {
	if b, err := asn1.Marshal(val); err != nil {
		panic(err)
	} else {
		return b
	}
}

func unmarshalEcParams(b []byte, ci curveInfo) (elliptic.Curve, error) {

	if bytes.Equal(b, ci.oid) {
		if ci.curve != nil {
			return ci.curve, nil
		}
		return nil, errors.New("Error  unmarshalEcParams")
	}

	return nil, errors.New("Error unmarshalEcParams")
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (*big.Int, *big.Int, error) {
	var pointBytes []byte
	extra, err := asn1.Unmarshal(b, &pointBytes)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "elliptic curve point is invalid ASN.1")
	}

	if len(extra) > 0 {
		// We weren't expecting extra data
		return nil, nil, errors.New("unexpected data found when parsing elliptic curve point")
	}

	x, y := elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		return nil, nil, errors.New("failed to parse elliptic curve point")
	}
	return x, y, nil
}

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// Populate a dsaSignature from DER encoding
func (sig *dsaSignature) unmarshalDER(sigDER []byte) error {
	if rest, err := asn1.Unmarshal(sigDER, sig); err != nil {
		return errors.WithMessage(err, "DSA signature contains invalid ASN.1 data")
	} else if len(rest) > 0 {
		return errors.New("unexpected data found after DSA signature")
	}
	return nil
}

func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return errors.New("DSA signature length is invalid from token")
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}

// ************** END COPY

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

	ci := &curveInfo{
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		elliptic.P256(),
	}

	parameters, err := marshalEcParams(elliptic.P256())
	if err != nil {
		panic(err)
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, parameters),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
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
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatalf("failed to generate exportable keypair: %s\n", err)
	}

	// Create a test signature and verify with keypair

	attr, err := p.GetAttributeValue(session, pbk, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		panic(err)
	}
	var ecpub ecdsa.PublicKey
	ecpub.Curve, err = unmarshalEcParams(attr[0].Value, *ci)
	if err != nil {
		panic(err)
	}
	if ecpub.X, ecpub.Y, err = unmarshalEcPoint(attr[1].Value, ecpub.Curve); err != nil {
		panic(err)
	}

	// https://github.com/ThalesGroup/crypto11/blob/master/ecdsa.go#L139
	encoded, err := x509.MarshalPKIXPublicKey(&ecpub)

	if err != nil {
		panic(err)
	}
	pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "ECC PUBLIC KEY", Bytes: encoded}))
	log.Printf("  Public Key: \n%s\n", pubkeyPem)

	msg := []byte("foo")
	digest := sha256.Sum256(msg)

	fmt.Printf("Signing %d bytes with %s\n", len(msg), msg)
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, pvk)
	if err != nil {
		log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
	}

	// Sign 'msg'
	var sig dsaSignature
	sigDER, err := p.Sign(session, digest[:])
	if err != nil {
		panic(err)
	}

	err = sig.unmarshalBytes(sigDER)
	if err != nil {
		panic(err)
	}

	log.Printf("Signature %s", base64.RawStdEncoding.EncodeToString(sigDER))

	ok := ecdsa.Verify(&ecpub, digest[:], sig.R, sig.S)
	if !ok {
		log.Printf("Failed verification.")
		return
	}

	log.Printf(">>>>>> Signature Verified")

}
