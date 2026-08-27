package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing uses PBKDF2-HMAC-SHA256, implemented on the standard
// library alone. The tracker deliberately ships with a single third-party
// dependency (the Postgres driver) so it can be built and run air-gapped;
// pulling in x/crypto for bcrypt would break that. PBKDF2 is a NIST-approved
// KDF and, at this iteration count, an appropriate choice for the threat model
// (an internal tool behind the corporate network).
const (
	pbkdf2Iterations = 600_000 // OWASP 2024 guidance for PBKDF2-HMAC-SHA256
	saltLen          = 16
	keyLen           = 32
)

var ErrBadHashFormat = errors.New("malformed password hash")

// HashPassword returns an encoded hash of the form
// pbkdf2$sha256$<iterations>$<base64 salt>$<base64 key>.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, keyLen)
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches the encoded hash. The
// comparison is constant-time.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false, ErrBadHashFormat
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil || iter <= 0 {
		return false, ErrBadHashFormat
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrBadHashFormat
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrBadHashFormat
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// pbkdf2SHA256 is PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 as the PRF.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen

	out := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, 4)
	u := make([]byte, hashLen)

	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		t := prf.Sum(nil)
		copy(u, t)

		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// otpAlphabet leaves out the characters people misread when copying a code out
// of an email: 0/O, 1/l/I. A shorter code that gets typed correctly beats a
// longer one that gets retyped three times.
const otpAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// OTPLength gives ~64 bits of entropy over the alphabet above, which is far
// more than the short expiry window and the one-per-cooldown rate limit need.
const OTPLength = 13

// NewOneTimePassword returns a random, human-transcribable temporary password,
// grouped into blocks for legibility. Rejection sampling keeps the alphabet
// uniform — a modulo bias here would shrink the search space for free.
func NewOneTimePassword() (string, error) {
	out := make([]byte, 0, OTPLength+3)
	buf := make([]byte, 1)
	max := byte(256 - (256 % len(otpAlphabet)))
	for i := 0; i < OTPLength; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			if buf[0] < max {
				break
			}
		}
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, otpAlphabet[int(buf[0])%len(otpAlphabet)])
	}
	return string(out), nil
}

// ValidatePasswordPolicy enforces the minimum the tracker will accept. Kept
// deliberately simple: length does more for entropy than character classes.
func ValidatePasswordPolicy(p string) error {
	if len([]rune(p)) < 10 {
		return errors.New("Password must be at least 10 characters")
	}
	if len(p) > 256 {
		return errors.New("Password must be at most 256 bytes")
	}
	return nil
}
