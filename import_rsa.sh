export SOFTHSM2_CONF=`pwd`/misc/softhsm.conf
rm -rf misc/tokens
mkdir misc/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-objects --pin mynewpin


go run import_rsa/import.go

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin

