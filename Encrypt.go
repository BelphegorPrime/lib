package lib

import (
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"io"
)

// Encrypts a text with aes in gcm mode and returns it as byte - array
// For every encryption will be a new nonce (12 byte) generated and placed at the start of the ciphertext
//
// The key parameter represents the symmetric key which will be used to encrypt a text
//
// The plainText parameter represents the text which will be encrypted
func AESEncrypt(key *[]byte, plainText []byte) (cipherText []byte) {

	block, err := aes.NewCipher(*key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	// Generate a new one for every encryption
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(crypto_rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ct := aesgcm.Seal(nil, nonce, plainText, nil)
	// The nonce don't has to be secret but only use it once !!!
	cipherText = append(nonce, ct...)

	return
}
