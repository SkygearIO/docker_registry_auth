package signing

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/docker/libtrust"
)

type Key struct {
	KeyID      string
	Algorithm  string
	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

func NewKey(certFile, keyFile string) (*Key, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	publicKey, err := libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	keyID := publicKey.KeyID()
	_, algorithm, err := privateKey.Sign(strings.NewReader("message"), 0)
	if err != nil {
		return nil, err
	}
	return &Key{
		KeyID:      keyID,
		Algorithm:  algorithm,
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func (k *Key) Sign(data []byte) ([]byte, error) {
	signature, _, err := k.privateKey.Sign(bytes.NewReader(data), 0)
	return signature, err
}
