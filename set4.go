package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func recoverPlaintext(inputFile string) []byte {
	var input string = readSmallFile(inputFile)

	// get plaintext
	fileBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	var output []byte = decryptAes128CBC(fileBytes, key, iv, false)
	fmt.Println(string(output))
	return output
}

func edit(ciphertext, key, nonce []byte, offset int, newtext []byte) []byte {
	plaintext := cryptAes128CTR(ciphertext, key, nonce)
	editedPlain := append(plaintext[:offset], newtext...)
	editedPlain = append(editedPlain, ciphertext[offset+len(newtext):]...)
	result := cryptAes128CTR(editedPlain, key, nonce)
	return result
}

func recoverPlaintextCTR(inputFile string) {
	plaintext := recoverPlaintext(inputFile)
	key := randBytes(16)
	nonce := make([]byte, 8)
	// creating fake ciphertext that we need to crack
	ciphertext := cryptAes128CTR(plaintext, key, nonce)
	newtext := make([]byte, len(ciphertext))
	keystreamResult := edit(ciphertext, key, nonce, 0, newtext)
	plaintextDecoded := fixedXOR(keystreamResult, ciphertext)
	if bytes.Compare(plaintextDecoded, plaintext) != 0 {
		panic("Shiiet")
	} else {
		fmt.Println("Hooray!")
	}
}
