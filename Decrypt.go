package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// Decrypts a text with aes in gcm mode nad returns it as a byte - array
// The nonce will be extract from the first 12 bytes from the cipherText
//
// The key parameter represents the symmetric key which will be used to decrypt a text
//
// The cipherText parameter represents the text which will be encrypted
func AESDecrypt(key *[]byte, cipherText []byte) (plainText []byte) {

	nonce := cipherText[:12]

	block, err := aes.NewCipher(*key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plainText, err = aesgcm.Open(nil, nonce, cipherText[len(nonce):], nil)
	if err != nil {
		panic(err.Error())
	}

	return
}
