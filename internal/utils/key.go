package utils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"reflect"

	"github.com/pkg/errors"
)

// ParsePrivateKeyPEM parse private key from PEM
func ParsePrivateKeyPEM(privateKeyPEM []byte) (key crypto.Signer, err error) {

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		err = errors.Errorf("decode pem private key failed.")
		return nil, err
	}

	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			err = errors.Wrap(err, "x509.ParsePKCS1PrivateKey(block.Bytes)")
			return nil, err
		}

		return key, nil
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.Errorf("not supported, type:%s", reflect.TypeOf(key).String())
		}

		return signer, nil
	} else if block.Type == "EC PRIVATE KEY" {
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}
