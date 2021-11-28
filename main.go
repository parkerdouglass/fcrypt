package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"io"
	"io/ioutil"
)

func main() {
	var file_path string
	var decrypt bool
	var encrypt bool
	var password string
	flag.StringVar(&file_path, "f", "", "The path to the file you want to encrypt/decrypt")
	flag.BoolVar(&decrypt, "d", false, "Used to tell the Command-line that you want to decrypt the file")
	flag.BoolVar(&encrypt, "e", false, "Used to tell the Command-line that you want to encrypt the file")
	flag.StringVar(&password, "p", "", "The password that will be used to encrypt/decrypt the file")
	flag.Parse()

	if decrypt {
		DecryptFile(file_path, password)
	} else if encrypt {
		EncryptFile(file_path, password)
	}

}

func EncryptFile(file_path string, password string) {
	text, err := ioutil.ReadFile(file_path)
	if err != nil {
		panic(err)
	}
	key := sha256.Sum256([]byte(password))

	// Create a new AES cipher
	block, err := aes.NewCipher(key[:])

	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	// Create a new nonce in place of an IV
	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	cText := gcm.Seal(nonce, nonce, text, nil)

	// Now, we write the encryption to the file
	ioutil.WriteFile(file_path, cText, 0777)

}

func DecryptFile(file_path string, password string) {
	cText, err := ioutil.ReadFile(file_path)
	if err != nil {
		panic(err)
	}

	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	gcm, err := cipher.NewGCM(block)
	nonce := cText[:gcm.NonceSize()]
	cText = cText[gcm.NonceSize():]
	pText, err := gcm.Open(nil, nonce, cText, nil)
	ioutil.WriteFile(file_path, pText, 0777)

}
