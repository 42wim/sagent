package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

const ed25519Label = "age-tool.com ssh-ed25519"
const oaepLabel = "age-tool.com ssh-rsa"

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) [32]byte {
	h := sha512.New()
	h.Write(pk[:32])
	out := h.Sum(nil)
	var res [32]byte
	copy(res[:], out)
	return res
}

func handleAgeDecrypt(k *sshKey, contents []byte) ([]byte, error) {
	var publicKey, sharedSecret, tweak [32]byte
	pk := k.pk.(*ed25519.PrivateKey)
	secretKey := ed25519PrivateKeyToCurve25519(*pk)
	tH := hkdf.New(sha256.New, nil, k.signer.PublicKey().Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&publicKey, &secretKey)
	var theirPublicKey [32]byte
	copy(theirPublicKey[:], contents)
	curve25519.ScalarMult(&sharedSecret, &secretKey, &theirPublicKey)
	curve25519.ScalarMult(&sharedSecret, &tweak, &sharedSecret)
	res := make([]byte, 0, 2*32)
	res = append(res, sharedSecret[:]...)
	res = append(res, publicKey[:]...)
	return res, nil
}
