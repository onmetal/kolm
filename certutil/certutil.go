// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/google/uuid"
	"k8s.io/client-go/util/cert"
)

func generatePrivateKey() (crypto.Signer, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating key: %w", err)
	}
	return caKey, nil
}

func generateSerial() (*big.Int, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating uuid: %w", err)
	}

	return big.NewInt(0).SetBytes(id[:]), nil
}

type Pair struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

func (p *Pair) CertBytes() ([]byte, error) {
	return EncodeCertificate(p.Cert)
}

func EncodeCertificate(cert *x509.Certificate) ([]byte, error) {
	if cert.Raw == nil {
		return nil, fmt.Errorf("certificate has no raw representation")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}

func EncodeKey(key crypto.Signer) ([]byte, error) {
	rawKeyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rawKeyData,
	}), nil
}

func (p *Pair) KeyBytes() ([]byte, error) {
	return EncodeKey(p.Key)
}

func (p *Pair) Bytes() (certBytes, keyBytes []byte, err error) {
	certBytes, err = p.CertBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate bytes: %w", err)
	}

	keyBytes, err = p.KeyBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting key bytes: %w", err)
	}

	return certBytes, keyBytes, nil
}

func WritePairFiles(pair *Pair, name string) error {
	crtBytes, keyBytes, err := pair.Bytes()
	if err != nil {
		return fmt.Errorf("error transforming pair to bytes: %w", err)
	}

	crtFilename := fmt.Sprintf("%s.crt", name)
	if err := os.WriteFile(fmt.Sprintf("%s.crt", name), crtBytes, 0666); err != nil {
		return fmt.Errorf("error writing certificate %s: %w", crtFilename, err)
	}

	keyFilename := fmt.Sprintf("%s.key", name)
	if err := os.WriteFile(keyFilename, keyBytes, 0666); err != nil {
		return fmt.Errorf("error writing key %s: %w", keyFilename, err)
	}

	return nil
}

func ReadPairFiles(name string) (*Pair, error) {
	crt, err := ReadCertificateFile(name)
	if err != nil {
		return nil, err
	}

	key, err := ReadKeyFile(name)
	if err != nil {
		return nil, err
	}

	return &Pair{Cert: crt, Key: key}, nil
}

func ReadKeyFile(name string) (crypto.Signer, error) {
	keyFilename := fmt.Sprintf("%s.key", name)
	keyBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		return nil, fmt.Errorf("error reading key %s: %w", keyFilename, err)
	}

	key, err := ParseKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ParseKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("key is not pem-encoded")
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %w", err)
	}

	key, ok := keyIface.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return key, nil
}

func ReadCertificateFile(name string) (*x509.Certificate, error) {
	crtFilename := fmt.Sprintf("%s.crt", name)
	crtBytes, err := os.ReadFile(crtFilename)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file %s: %w", crtFilename, err)
	}

	crt, err := ParseCertificateBytes(crtBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate bytes: %w", err)
	}
	return crt, nil
}

func ParseCertificateBytes(crtBytes []byte) (*x509.Certificate, error) {
	crtBlock, _ := pem.Decode(crtBytes)
	if crtBlock == nil {
		return nil, fmt.Errorf("certificate is not pem-encoded")
	}
	crt, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}
	return crt, nil
}

func GenerateSelfSignedCA(commonName string, organization []string) (*Pair, error) {
	key, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	cfg := cert.Config{
		CommonName:   commonName,
		Organization: organization,
	}

	crt, err := cert.NewSelfSignedCACert(cfg, key)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate for ca: %w", err)
	}

	return &Pair{
		Key:  key,
		Cert: crt,
	}, nil
}

func GenerateCertificate(parent *Pair, cfg cert.Config) (*Pair, error) {
	now := time.Now()

	key, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, err
	}

	crtTemplate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: cfg.CommonName, Organization: cfg.Organization},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
		NotBefore:    now.UTC(),
		NotAfter:     now.Add(168 * time.Hour).UTC(),
	}
	crtData, err := x509.CreateCertificate(crand.Reader, crtTemplate, parent.Cert, key.Public(), parent.Key)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtData)
	if err != nil {
		return nil, fmt.Errorf("error parsing created certificate: %w", err)
	}

	return &Pair{
		Key:  key,
		Cert: crt,
	}, nil
}
