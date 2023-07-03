# PKCS 11 Samples in Go using SoftHSM

This repo contains several sample usage of golang and [PKCS11](https://en.wikipedia.org/wiki/PKCS_11).

Specifically, this contains:

- `import_rsa_aes/`: Wrapping and Importing an RSA key using an AES key 
- `import_aes_rsa/`: Wrapping and Importing an AES key using an RSA key
- `hmac/`: Importing an HMAC key into PKCS-11
- `aes_encrypt/`:  AES Encrypt/Decrypt
- `rsa_sign/`: Sign/Verify using RSA
- `import_rsa/`: Create an RSA keypair by specifying the parameters
- `pkcs_uri/`: Parse and PKCS URI formatted string for RSA sign/verify

and various functions using `pkcs11-tool` to generate keys on TPM/Yubikey and SoftHSM


>> **NOTE**, The golang samples has only been tested on SoftHSM.  Other types of PKCS11 devices like TPM, YubiKey all have different capabilities and variations.  It is highly likely functions below are not supported there.  


To use these samples, first install [SoftHSM](https://github.com/opendnssec/SoftHSMv2) and set the path appropriately:

```bash
# edit /path/to/go_pkcs11/misc/softhsm.conf
# set directories.tokendir = /path/to/go_pkcs11/misc/tokens


export SOFTHSM2_CONF=/path/to/go_pkcs11/misc/softhsm.conf

# list supported mechanisms
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms --slot-index 0
```


### References

- [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)
- [https://github.com/google/pkcs11test](https://github.com/google/pkcs11test)
- [https://github.com/OpenSC/OpenSC/blob/master/src/tools/pkcs11-tool.c#L3189](https://github.com/OpenSC/OpenSC/blob/master/src/tools/pkcs11-tool.c#L3189)
- [https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11)
- [https://github.com/IBM-Cloud/hpcs-grep11-go/blob/master/examples/server.go](https://github.com/IBM-Cloud/hpcs-grep11-go/blob/master/examples/server.go)
- [https://github.com/letsencrypt/pkcs11key/blob/master/key.go](https://github.com/letsencrypt/pkcs11key/blob/master/key.go)


---


## Wrapping RSA key with AES key

see `rsa_aes/import.go`:

In this mode, we will:

1. Create AES key which is enabled for wrapping
```golang
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
```

2. Use it to encrypt/decrypt some sample data

THis is just to test, its not necessary for wrap/unwrap

3. Create RSA keypair enabled for extraction

```golang
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

```

4. Sign and verify data with the RSA key

This is just for testing; its not necessary for wrapping


5. Wrap the RSA key with AES key

```golang
	wrappedPrivBytes, err := p.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, pvk)
```

6. Unwrap the RSA key with the AES key

```golang
	ik, err := p.UnwrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, wrappedPrivBytes, importedPrivateKeyTemplate)
```

7. Use the unwrapped key to sign/verify

Since its the same key we used, we should see the same signature as step 4

```log
$ go run aes_rsa/import.go 
CryptokiVersion.Major 2
2021/05/17 19:30:37 Created AES Key: 2
2021/05/17 19:30:37 Encrypted IV+Ciphertext 6xEZldVQCbL/uahW2I68nUG35HUVrPZu9NyqKV+H8c4
2021/05/17 19:30:37 Decrypt foo
2021/05/17 19:30:37   Public Key: 
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxlGKaAhr0eL/DjhAMsPTDjqD0SwsLyqm0O24j2dREWtQ8KogOE39
VUDFNbccBzJm4TQGSEgzcDJYsfk9UieEWu03Xas2KaU6LvE1z1LiakUUvJ/pgmA/
MElbTGY7nugh6YOlaGhK4JVi+XXrvI7uah8fkOvitIxABpQv+T8kPkC1yLSg0GHe
DPd2GuNcgsfeVCQqC86NPOy5HVCTD2ZA0Y0uREGK/uM3zeWNUdDjQo6wO3Cw7A1C
S8MQ6Xcjhq4T3dJGjFuZVkiP1+6Daj8UKoVLDnMXy28r07IloAEZFTe/QZyadJjC
BGTYVWWBwqy4au/sSW6kaTZnHiXml96aEQIDAQAB
-----END RSA PUBLIC KEY-----

Signing 3 bytes with foo
2021/05/17 19:30:37 Signature vN+te5+tlO6avoDIV50wZZJP2Mj8VO7/9IN+CVljyHAcHijw3hF1itUMgflyycnj1WNNjVFf0WDvSzI7LYslh9BkBw1bdQxBc5L15yzG6UsVNzjrn+JFNpl6LtnVgClEAfBeC6giqZAT1WL/rDm3GHWnOpVYJcTe1MUHHYT2QFGV996aCyBV5TpW8eLr3Jc8vcQhhebLhAlviCvyefLeBEafXvtVD5erErl+DPQAChEjmyJkyVJy6R5xrLtlM7sUydPMygztsQxm3STp3uYu7TDuibl75H4iJ/7dcGSOMP/6pBUBKA4sGDZQpNX9rJIw5DyEiYDk9JMbVgjEZDqAEQ
2021/05/17 19:30:37 >>>>>> Signature Verified
Signing 3 bytes with foo
2021/05/17 19:30:37 Signature vN+te5+tlO6avoDIV50wZZJP2Mj8VO7/9IN+CVljyHAcHijw3hF1itUMgflyycnj1WNNjVFf0WDvSzI7LYslh9BkBw1bdQxBc5L15yzG6UsVNzjrn+JFNpl6LtnVgClEAfBeC6giqZAT1WL/rDm3GHWnOpVYJcTe1MUHHYT2QFGV996aCyBV5TpW8eLr3Jc8vcQhhebLhAlviCvyefLeBEafXvtVD5erErl+DPQAChEjmyJkyVJy6R5xrLtlM7sUydPMygztsQxm3STp3uYu7TDuibl75H4iJ/7dcGSOMP/6pBUBKA4sGDZQpNX9rJIw5DyEiYDk9JMbVgjEZDqAEQ

```

8. Print object to see the new key

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```


## Wrapping AES key with RSA key

In this mode, we will do the inverse where we generate and AES key which we will wrap/unwrap with RSA key


see `aes_rsa/import.go`:


1. First create AES key suitable with `CKA_EXTRACTABLE`

```golang
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
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true), // we do need to extract this
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKeyToWrap"),   /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
```

2. Use it to encrypt/decrypt some sample data

This is just to test, its not necessary for wrap/unwrap


3. Create RSA key enabled for `CKA_WRAP/CKA_UNWRAP`

```golang
	wpublicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, wpubID),
	}
	wprivateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappriv1"),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, wprivID),
	}
```

4. Wrap AES key with RSA

```golang
wrappedPrivBytes, err := p.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, wpbk, aesKey)
```

5. Unwrap Key with RSA Private Key

```golang
	aesKeyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "UnwrappedAESKey"), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, importedPrivID),
	}

	// B) unwrap AES key using RSA Public Wrapping Key
	ik, err := p.UnwrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, wpvk, wrappedPrivBytes, aesKeyTemplate)
```

6. Print new key

```
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```

## Wrapping RSA key with RSA key


Ref:
-- [2.1.21 RSA AES KEY WRAP](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850425)

```
2.1.21 RSA AES KEY WRAP

The RSA AES key wrap mechanism, denoted CKM_RSA_AES_KEY_WRAP , is a mechanism based on the RSA public-key cryptosystem and the AES key wrap mechanism.  It supports single-part key wrapping; and key unwrapping.

It has a parameter, a CK_RSA_AES_KEY_WRAP_PARAMS structure.

The mechanism can wrap and unwrap a target asymmetric key of any length and type using an RSA key.
```

>> i do not think ths is supported with softHSM [Issue#424](https://github.com/opendnssec/SoftHSMv2/issues/424)

```bash
# softHSM
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms
	Using slot 0 with a present token (0x5a975eb5)
	RSA-PKCS, keySize={512,16384}, encrypt, decrypt, sign, verify, wrap, unwrap
	RSA-PKCS-KEY-PAIR-GEN, keySize={512,16384}, generate_key_pair
	RSA-PKCS-OAEP, keySize={512,16384}, encrypt, decrypt, wrap, unwrap
	RSA-PKCS-PSS, keySize={512,16384}, sign, verify
	RSA-X-509, keySize={512,16384}, encrypt, decrypt, sign, verify

	AES-KEY-WRAP, keySize={16,2147483648}, wrap, unwrap

# Yubikey
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-mechanisms | grep RSA
	Using slot 0 with a present token (0x0)
	RSA-X-509, keySize={1024,3072}, hw, decrypt, sign, verify
	RSA-PKCS, keySize={1024,3072}, hw, decrypt, sign, verify
	SHA1-RSA-PKCS, keySize={1024,3072}, sign, verify
	SHA224-RSA-PKCS, keySize={1024,3072}, sign, verify
	SHA256-RSA-PKCS, keySize={1024,3072}, sign, verify
	SHA384-RSA-PKCS, keySize={1024,3072}, sign, verify
	SHA512-RSA-PKCS, keySize={1024,3072}, sign, verify
	MD5-RSA-PKCS, keySize={1024,3072}, sign, verify
	RIPEMD160-RSA-PKCS, keySize={1024,3072}, sign, verify
	RSA-PKCS-PSS, keySize={1024,3072}, hw, sign, verify
	SHA1-RSA-PKCS-PSS, keySize={1024,3072}, sign, verify
	SHA224-RSA-PKCS-PSS, keySize={1024,3072}, sign, verify
	SHA256-RSA-PKCS-PSS, keySize={1024,3072}, sign, verify
	SHA384-RSA-PKCS-PSS, keySize={1024,3072}, sign, verify
	SHA512-RSA-PKCS-PSS, keySize={1024,3072}, sign, verify

$  pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-mechanisms | grep WRAP
	Using slot 0 with a present token (0x0)

# TPM
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-mechanisms
	Using slot 0 with a present token (0x1)
	Supported mechanisms:
	RSA-PKCS-KEY-PAIR-GEN, keySize={1024,2048}, hw, generate_key_pair
	RSA-X-509, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
	RSA-PKCS, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
	RSA-PKCS-OAEP, keySize={1024,2048}, hw, encrypt, decrypt
	SHA1-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	SHA256-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	SHA384-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	ECDSA-KEY-PAIR-GEN, keySize={224,521}, hw, generate_key_pair
	ECDSA, keySize={224,521}, hw, sign, verify
	ECDSA-SHA1, keySize={224,521}, hw, sign, verify
	AES-KEY-GEN, keySize={16,32}, hw, generate
	AES-CBC, keySize={16,32}, hw, encrypt, decrypt
	mechtype-0x2107, keySize={16,32}, hw, encrypt, decrypt
	AES-ECB, keySize={16,32}, hw, encrypt, decrypt
	SHA-1, digest
	SHA256, digest
	SHA384, digest
	SHA512, digest
```

Instead, i **think** the procedure to transfer an RSA private key from HSM_A to HSM_B goes like this using (`aes_rsa/import.go` and `rsa_aes/import.go`):

1. Generate an RSA keypair on HSM_B (`HSM_B_RSA_PUB_W`, `HSM_B_RSA_PRIV_W`) capable of wrapping
2. Export the public RSA wrapping key (`HSM_B_RSA_PUB_W`)
3. Provide the Public RSA wrapping key (`HSM_B_RSA_PUB_W`) to HSM_A
4. HSM_A imports `HSM_B_RSA_PUB_W`
5. HSM_A generates AES key  (`HSM_A_AES_W`) capable of wrapping
6. HSM_A wraps `HSM_A_AES_W` with `HSM_B_RSA_PUB_W`
7. HSM_A transfers wrapped `HSM_A_AES_W` to HSM_B
8. HSM_B imports `HSM_A_AES_W`
9. HSM_A generates keypair (`HSM_A_RSA_PUB`, `HSM_A_RSA_PRIV`)
10. HSM_A wraps (`HSM_A_RSA_PUB`, `HSM_A_RSA_PRIV`) with (`HSM_A_AES_W`)
11. HSM_A transfers wrapped RSA keys from to HSM_B
12. HSM_B uses imported (`HSM_A_AES_W`) from step 8 to unwrap the transferred keys.

<< do not do this...i'm unsure if this is the correct protocol!


also see [Importing a manually-wrapped key](https://cloud.google.com/kms/docs/importing-a-key#importing_a_manually-wrapped_key). 

## Importing RSA Cert and Key using pkcs11-tool

```bash
# first convert the PEM cert and KEY to DER
openssl x509 -in sts.crt -out sts.crt.der -outform DER 
openssl rsa -inform pem -in sts.key -outform der -out sts.key.der

# Reset softHSM

cd mtls_pkcs11/misc/softhsm.conf
rm -rf tokens
mkdir tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin


pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

# import key and cert
pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --pin mynewpin \
   --write-object sts.crt.der --type cert --id 10 --label keylabel3 --slot-index 0

pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --pin mynewpin \
   --write-object sts.key.der --type privkey --id 10 --label keylabel3 --slot-index 0

# list objects
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```

### Importing RSA key pair using modulus and exponent

- `import_rsa/`: Create an RSA keypair by specifying the parameters


First create RSA Keypair:

```bash
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -outform PEM -pubout -out pub.pem
openssl rsa -noout -text -inform PEM -in priv.pem

openssl rsa -pubin -in pub.pem -RSAPublicKey_out
openssl rsa -pubin -in pub.pem -text -noout
```

Reference: [pkcs11-tool.c](https://github.com/OpenSC/OpenSC/blob/master/src/tools/pkcs11-tool.c#L3189)


### Parsing PKCS URI

The following uses a helper library to parse a [PKCS URI](https://datatracker.ietf.org/doc/html/rfc7512)

With the softhsm config below

- `softhsm.conf`

```conf
log.level = DEBUG
objectstore.backend = file
directories.tokendir = /tmp/soft_hsm/tokens
slots.removable = true
```

Create an RSA keypair

```bash
$ mkdir -p /tmp/soft_hsm/tokens

$ export SOFTHSM2_CONF=`pwd`/softhsm.conf

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots

      Using slot 0 with a present token (0x34a7cbb6)
      User PIN successfully initialized
      Available slots:
      Slot 0 (0x34a7cbb6): SoftHSM slot ID 0x34a7cbb6
        token label        : token1
        token manufacturer : SoftHSM project
        token model        : SoftHSM v2
        token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
        hardware version   : 2.6
        firmware version   : 2.6
        serial num         : 71bc89cdb4a7cbb6
        pin min/max        : 4/255
      Slot 1 (0x1): SoftHSM slot ID 0x1
        token state:   uninitialized


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin

      Using slot 0 with a present token (0x34a7cbb6)
      Key pair generated:
      Private Key Object; RSA 
        label:      keylabel1
        ID:         4142
        Usage:      decrypt, sign, unwrap
        Access:     sensitive, always sensitive, never extractable, local
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects 

      Using slot 0 with a present token (0x34a7cbb6)
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local

        

$ softhsm2-util --show-slots
      Available slots:
      Slot 883411894
          Slot info:
              Description:      SoftHSM slot ID 0x34a7cbb6                                      
              Manufacturer ID:  SoftHSM project                 
              Hardware version: 2.6
              Firmware version: 2.6
              Token present:    yes
          Token info:
              Manufacturer ID:  SoftHSM project                 
              Model:            SoftHSM v2      
              Hardware version: 2.6
              Firmware version: 2.6
              Serial number:    71bc89cdb4a7cbb6
              Initialized:      yes
              User PIN init.:   yes
              Label:            token1                          
      Slot 1
          Slot info:
              Description:      SoftHSM slot ID 0x1                                             
              Manufacturer ID:  SoftHSM project                 
              Hardware version: 2.6
              Firmware version: 2.6
              Token present:    yes
          Token info:
              Manufacturer ID:  SoftHSM project                 
              Model:            SoftHSM v2      
              Hardware version: 2.6
              Firmware version: 2.6
              Serial number:                    
              Initialized:      no
              User PIN init.:   no
              Label:                                            
```

Note the `Serial Number` from command above.  Use that in the PKCS URI below.

For me it was

* slot-id = hex `0x34a7cbb6` => `883411894`
* serial = `71bc89cdb4a7cbb6`

so,

```bash
export PKCS11_URI="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;slot-id=883411894;serial=71bc89cdb4a7cbb6;token=token1;object=keylabel1;id=4142?pin-value=mynewpin&module-path=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

go run main.go $PKCS11_URI

      slot-id 883411894
      Token token1
      id 4142
      Object keylabel1

        Public Key: 
      -----BEGIN RSA PUBLIC KEY-----
      MIIBCgKCAQEA2v98/uTkJXKg9AV70Ac9Hz7F57LUgxjHbFrVYYZTsClHnxw4lvS7
      qhh3Mb56ss14s+ntjabqbuwZiEocY7JylqzPrRh8SOzjjceR3Qsn1toAobdznMC4
      rCueQF0Da01gzPcxle2Vx3h9NLVHoreUOoOG4zjzYYIsKljmzw95ZacEiXmEiKLD
      aOFewoRHo+jWCZHfno647JLtj/GydLg/J9MMeIrbFIqGdc1JnbV/FaqjYtgif7UR
      kcXjginBK/fwXkDSY01eV9LIqWICP8RnNUPcijYGkNWgI0h5ne4hGMVWSpPZftqB
      0jZ+9oBbFkRmaHNRUw0CQdx5hZojSKm5vQIDAQAB
      -----END RSA PUBLIC KEY-----

      Signature FfrurtcvrIt/R7r13H2Kd91KirwEUG9tifF2+Skde5D98VCqAvBWwZPhTKsUO+YshCwry2V51T/nMBwsYSSdffBjd+Ok2+P+c7443zngaBQO1ocdygiFHu8kniIAYxEHYmhq1Ue8UHxtKGKF5OTbewrlXxxs4aS5b2z5jsOfDnirTlFSDSn9fyKMMQEKi+IJFX0qVudLHEr7x2LxOprEsaYyrScVn0pnrdXZ332L7aACbbDcHWPNdrtR/HTXLsxABlynFGhOPhno3eqmUCL47tmtc5Ce85SQHcEb+TIMBaqRs20oBpMBvAKwW379kKT1moYJePp+eRvgBF1watUuDA
      Signature Verified

```


---

### Appendix

The following describes using `pkcs11-tool` to setup the mTLS configuration for YubiKey and TPM:

#### Yubikey

Install module references for openssc-pkcs11.so and `libykcs11.so`

- [OpenSC’s pkcs11-tool](https://developers.yubico.com/yubico-piv-tool/YKCS11/Supported_applications/pkcs11tool.html)
- [OpenSSL with YubiHSM 2 via engine_pkcs11 and yubihsm_pkcs11](https://developers.yubico.com/YubiHSM2/Usage_Guides/OpenSSL_with_pkcs11_engine.html)

The following assumes you already setup a KeyPair on the Yubikey using the commands above

```bash
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --list-objects

Public Key Object; RSA 2048 bits
  label:      Public key for Digital Signature
  ID:         02
  Usage:      encrypt, verify

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-token-slots 
    Available slots:
    Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
      token label        : user1_esodemoapp2_com
      token manufacturer : piv_II
      token model        : PKCS#15 emulated
      token flags        : login required, rng, token initialized, PIN initialized
      hardware version   : 0.0
      firmware version   : 0.0
      serial num         : 993084513cb2a39d
      pin min/max        : 4/8


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-objects
    Using slot 0 with a present token (0x0)
    Public Key Object; RSA 2048 bits
      label:      PIV AUTH pubkey
      ID:         01
      Usage:      encrypt, verify, wrap
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for PIV Authentication
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1_esodemoapp2_com
      ID:         01
    Public Key Object; RSA 2048 bits
      label:      SIGN pubkey
      ID:         02
      Usage:      encrypt, verify, wrap
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for Digital Signature
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=yubikey-svc@mineral-minutia-820.iam.gserviceaccount.com
      ID:         02
    Public Key Object; RSA 2048 bits
      label:      KEY MAN pubkey
      ID:         03
      Usage:      encrypt
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for Key Management
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1@esodemoapp2.com
      ID:         03


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --label="SIGN pubkey" --pin 123456 --generate-random 50 | xxd -p
Using slot 0 with a present token (0x0)
c621e081d3a0ed5c10f1dceea80380785612b792697242802c85ec1b6fc7
6b83dd4f00c002edb526f6d6e3ab63e407c643af


export PKCS11_PRIVATE_KEY="pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=993084513cb2a39d;token=user1_esodemoapp2_com;type=private;id=%02?pin-value=123456"
export PKCS11_PUBLIC_KEY="pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=993084513cb2a39d;token=user1_esodemoapp2_com;type=public;id=%02?pin-value=123456"

### Display the public key
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout

### Sign and verify
echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig
```

#### TPM

To use a TPM, you must have a machine with a TPM installed (ofcourse)...for example a Google Cloud Shielded VM.  Your laptop also likely has one but i'd recommend not messing around with it

- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2): Samples for using TPMs in golang
- [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed):  mTLS with TPM backed keys using [go-tpm](https://github.com/google/go-tpm-tools).  This does not use PKCS11


```bash
$ vi /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main

$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc -y
```

```bash
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-mechanisms --slot-index 0
	Using slot with index 0 (0x1)
	Supported mechanisms:
	RSA-PKCS-KEY-PAIR-GEN, keySize={1024,2048}, hw, generate_key_pair
	RSA-X-509, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
	RSA-PKCS, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
	RSA-PKCS-OAEP, keySize={1024,2048}, hw, encrypt, decrypt
	SHA1-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	SHA256-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	SHA384-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
	ECDSA-KEY-PAIR-GEN, keySize={224,521}, hw, generate_key_pair
	ECDSA, keySize={224,521}, hw, sign, verify
	ECDSA-SHA1, keySize={224,521}, hw, sign, verify
	AES-KEY-GEN, keySize={16,32}, hw, generate
	AES-CBC, keySize={16,32}, hw, encrypt, decrypt
	mechtype-0x2107, keySize={16,32}, hw, encrypt, decrypt
	AES-ECB, keySize={16,32}, hw, encrypt, decrypt
	SHA-1, digest
	SHA256, digest
	SHA384, digest
	SHA512, digest
```

Now use `pkcs-tools` to genrate a keypair...you can also import one or reference one thats already present..but the following creates one from scratch:

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --slot-index=0 --init-token --label="token1" --so-pin="mysopin"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --label="token1" --init-pin --so-pin mysopin --pin mynewpin
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-token-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --label="keylabel1" --login  --pin=mynewpin --id 0  --keypairgen --key-type rsa:2048

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  --label="keylabel1" --pin mynewpin --generate-random 50 | xxd -p

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-slots
    Available slots:
    Slot 0 (0x1): token1                          GOOG
    token label        : token1
    token manufacturer : GOOG
    token model        : vTPM
    token flags        : login required, rng, token initialized, PIN initialized
    hardware version   : 1.42
    firmware version   : 22.17
    serial num         : 0000000000000000
    pin min/max        : 0/128
    Slot 1 (0x2):                                 GOOG
    token state:   uninitialized


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-objects

  Using slot 0 with a present token (0x1)
  Public Key Object; RSA 2048 bits
    label:      keylabel1
    Usage:      encrypt, verify
    Access:     local
```

Specify the MODULE for tpm in `/etc/ssl/openssl.cnf`

```bash
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1
```

```bash
export PKCS11_PUBLIC_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=public;object=keylabel1?pin-value=mynewpin"
export PKCS11_PRIVATE_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=private;object=keylabel1?pin-value=mynewpin"

### Display the public key

openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout

### Sign and verify

echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig
```

