package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

// A v3 approval token is a compact JWS whose protected header names the key
// that signed it. Only ES256 is accepted, and the key comes from the set the
// caller holds, never from the token: no jwk, jku or x5c header is read.
// Nothing in this file touches the HMAC secret.

const (
	jwsAlg         = "ES256"
	jwsType        = "wardryx-approval+jwt"
	maxKidLength   = 128
	claimsVersion3 = 3
	rawSigLength   = 64 // r || s, 32 bytes each, as Keyryx returns it
)

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// mintV3 signs the claims as a v3 token. The header's kid is the one Current
// reported; when Sign answers with a different kid the key moved between the
// two calls, and the token is signed again under the kid that answered. A
// second move fails the grant.
func mintV3(ctx context.Context, signer Signer, c claims, ttl time.Duration) (string, error) {
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	c.V = claimsVersion3
	c.Nonce = nonce
	c.Exp = time.Now().Add(ttl).Unix()
	if c.ToolCallDigest != "" && !validToolCallDigest(c.ToolCallDigest) {
		return "", ErrToolCallContext
	}
	kid, err := signer.Current(ctx)
	if err != nil || kid == "" {
		return "", fmt.Errorf("%w: no current key", ErrSigner)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("approval: marshal claims: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	for attempt := 0; attempt < 2; attempt++ {
		hdr, err := json.Marshal(jwsHeader{Alg: jwsAlg, Kid: kid, Typ: jwsType})
		if err != nil {
			return "", fmt.Errorf("approval: marshal header: %w", err)
		}
		input := base64.RawURLEncoding.EncodeToString(hdr) + "." + body
		signed, sig, err := signer.Sign(ctx, []byte(input))
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrSigner, err)
		}
		if signed == kid {
			if len(sig) != rawSigLength {
				return "", fmt.Errorf("%w: a signature of %d bytes is not ES256", ErrSigner, len(sig))
			}
			return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
		}
		if signed == "" {
			return "", fmt.Errorf("%w: a signature without a kid", ErrSigner)
		}
		kid = signed
	}
	return "", fmt.Errorf("%w: the signing key moved twice during one grant", ErrSigner)
}

// parseV3 checks the header, then the signature under the kid it names, and
// only then reads the claims.
func (k Keys) parseV3(token string) (claims, error) {
	if k.JWKS == nil {
		return claims{}, ErrNoKeys
	}
	parts := strings.Split(token, ".")
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, fmt.Errorf("%w: header: %v", ErrTokenMalformed, err)
	}
	var h jwsHeader
	dec := json.NewDecoder(bytes.NewReader(hdrBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return claims{}, fmt.Errorf("%w: header: %v", ErrTokenMalformed, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return claims{}, fmt.Errorf("%w: data after the header", ErrTokenMalformed)
	}
	if h.Alg != jwsAlg || h.Typ != jwsType || h.Kid == "" || len(h.Kid) > maxKidLength {
		return claims{}, fmt.Errorf("%w: header %q/%q", ErrTokenMalformed, h.Alg, h.Typ)
	}
	pub, ok := k.JWKS.Key(h.Kid)
	if !ok {
		return claims{}, ErrTokenUnknownKid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != rawSigLength {
		return claims{}, ErrTokenSignature
	}
	signingInput := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, signingInput[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return claims{}, ErrTokenSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, fmt.Errorf("%w: claims: %v", ErrTokenMalformed, err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, fmt.Errorf("%w: claims: %v", ErrTokenMalformed, err)
	}
	if c.V != claimsVersion3 {
		return claims{}, fmt.Errorf("%w: %d", ErrTokenVersion, c.V)
	}
	if c.AID == "" {
		return claims{}, fmt.Errorf("%w: no approval id", ErrTokenMalformed)
	}
	if c.ToolCallDigest != "" && !validToolCallDigest(c.ToolCallDigest) {
		return claims{}, fmt.Errorf("%w: no usable tool-call digest", ErrTokenMalformed)
	}
	return c, nil
}
