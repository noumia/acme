package acme

import (
	"crypto"
	"crypto/ecdsa"
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

	if key, ok := pub.(*ecdsa.PublicKey); ok {
		p := key.Curve.Params()
		n := (p.BitSize + 7) / 8
		x := key.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := key.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		jwk := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y))

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

func Hasher(key crypto.Signer) (string, crypto.Hash) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PrivateKey:
		switch key.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-521":
			return "ES512", crypto.SHA512
		}
	}
	return "", 0
}

func Sign(key crypto.Signer, hasher crypto.Hash, digest []byte) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return key.Sign(rand.Reader, digest, hasher)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := (key.Params().BitSize + 7) / 8
		sig := make([]byte, size*2)
		copy(sig[size-len(rb):], rb)
		copy(sig[size*2-len(sb):], sb)
		return sig, nil
	}
	return nil, errors.New("Unsupported.Key")
}

func EncodeJWS(claimset interface{}, key crypto.Signer, nonce string, kid string, url string) ([]byte, error) {
	alg, hasher := Hasher(key)

	var header string
	if kid != "" {
		header = fmt.Sprintf(`{"alg":%q,"kid":%q,"nonce":%q,"url":%q}`, alg, kid, nonce, url)

	} else {
		jwk, err := EncodeJWK(key.Public())
		if err != nil {
			return nil, err
		}

		header = fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q,"url":%q}`, alg, jwk, nonce, url)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	/* */

	payload, err := json.Marshal(claimset)
	if err != nil {
		return nil, err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	/* */

	hash := hasher.New()
	hash.Write([]byte(headerB64 + "." + payloadB64))

	sig, err := Sign(key, hasher, hash.Sum(nil))
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
