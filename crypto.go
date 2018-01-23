package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

func EncodeJWK(pub crypto.PublicKey) (string, error) {
	if key, ok := pub.(*rsa.PublicKey); ok {
		n := key.N
		e := big.NewInt(int64(key.E))
		jwk := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()))

		return jwk, nil
	}

	return "", errors.New("Unsupported.Key")
}

func ThumbprintJWK(pub crypto.PublicKey) (string, error) {
	jwk, err := EncodeJWK(pub)
	if err != nil {
		return "", err
	}
	by := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(by[:]), nil
}

func EncodeJWS(claimset interface{}, key crypto.Signer, nonce string, kid string, url string) ([]byte, error) {
	var header string
	if kid != "" {
		header = fmt.Sprintf(`{"alg":"RS256","kid":%q,"nonce":%q,"url":%q}`, kid, nonce, url)

	} else {
		jwk, err := EncodeJWK(key.Public())
		if err != nil {
			return nil, err
		}

		header = fmt.Sprintf(`{"alg":"RS256","jwk":%s,"nonce":%q,"url":%q}`, jwk, nonce, url)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	/* */

	payload, err := json.Marshal(claimset)
	if err != nil {
		return nil, err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	/* */

	hash := crypto.SHA256.New()
	hash.Write([]byte(headerB64 + "." + payloadB64))

	sig, err := key.Sign(rand.Reader, hash.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}

	/* */

	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Sig       string `json:"signature"`
	}{
		Protected: headerB64,
		Payload:   payloadB64,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}

	return json.Marshal(&enc)
}

func KeyAuthorization(pub crypto.PublicKey, token string) (string, error) {
	thum, err := ThumbprintJWK(pub)
	if err != nil {
		return "", err
	}

	ka := token + "." + thum

	return ka, nil
}

func DNS01Challenge(pub crypto.PublicKey, token string) (string, error) {
	ka, err := KeyAuthorization(pub, token)
	if err != nil {
		return "", err
	}

	by := sha256.Sum256([]byte(ka))

	challenge := base64.RawURLEncoding.EncodeToString(by[:])

	return challenge, nil
}
