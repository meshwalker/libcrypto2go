package libCrypto2Go

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/scrypt"
)


const (
	// Key length and salt length are 32 bytes (256 bits)
	KEYLENGTH int       = 32

	// scrypt default parameters
	SCRYPT_CONST_N int  = 16384
	SCRYPT_CONST_R int  = 8
	SCRYPT_CONST_P int  = 1
)


func GenKey(password []byte, salt []byte ) ([]byte, error) {
	encryptedKey, err := scrypt.Key(password, salt, SCRYPT_CONST_N, SCRYPT_CONST_R, SCRYPT_CONST_P, KEYLENGTH)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}


func GenRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}


func Sum256(password string) (string) {
	buf := []byte(password)
	hash := sha3.Sum256(buf)
	return string(hash[:]);
}


func Sum384(password string) (string) {
	buf := []byte(password)
	hash := sha3.Sum384(buf)
	return string(hash[:])
}


func Sum512(password string) (string) {
	buf := []byte(password)
	hash := sha3.Sum512(buf)
	return string(hash[:])
}


func ShakeSum256(password string) ([]byte) {
	buf := []byte(password)
	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	h := make([]byte, 64)
	// Compute a 64-byte hash of buf and put it in h.
	sha3.ShakeSum256(h, buf)
	return h;
}