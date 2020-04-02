package main

import (
	// "encoding/hex"
	// "encoding/base64"
	// "fmt"
	// "os"
	// "sort"
	// "bufio"
	// "strings"
	// "bytes"
	// "math"
	"crypto/aes"
)

//challenge1 main
func padPlaintext(plaintext []byte, desiredSize int) []byte {
    padding := make([]byte, desiredSize-len(plaintext))
    for i := 0; i < len(padding); i ++ {
      padding[i] = byte(desiredSize-len(plaintext))
    }
    plaintext = append(plaintext, padding...)
    return plaintext
}

//challenge2 nonsense

/*
  I must say I'm a little confused by the first sentence of the
  description/precis for this challenge, which states: "CBC mode is a block
  cipher mode that allows us to encrypt irregularly-sized messages, despite the
  fact that a block cipher natively only transforms individual blocks." All you
  need to do to deal with irregularly-sized messages is pad out the messages in
  a pre-defined way. I guess they're talking about this -
  https://en.wikipedia.org/wiki/Ciphertext_stealing - except that this practice
  of "Ciphertext stealing" (a.k.a. padding without padding) can also be used in
  ECB mode. The only difference is this: "Ciphertext stealing for ECB mode
  requires the plaintext to be longer than one block." Whichever way you spin
  it, it's a misleading statement. And, most confusingly at all, no form of
  Ciphertext stealing is relevant to this challenge.

  There have been several confusing sentences like this so far in this set of
  challenges. I wish they were less cryptic with their instructions and
  exposition. It has caused me to waste some time. And my time is precious
  goddamnit!

  Also I'm mad at these fuckers for not telling me that the 10.txt is base64
  encoded after the AES encryption.. EXTREMELY MAD. Maybe it should have been
  obvious... but nah
*/
func encryptAes128CBC(plaintext, key, iv []byte) []byte {
    cipher, _ := aes.NewCipher([]byte(key))
    modVal := len(plaintext)%16
    if modVal != 0 {
        panic("We have not specified a padding scheme so this plaintext of irregular length is verboten!")
    }
    ciphertext := make([]byte, len(plaintext))
    size := 16
    prevBlock := iv
    //doing 'manual' application of XOR as instructed rather than using library functions (beyond 'cipher.Encrypt')
    for bs, be := 0, size; bs < len(plaintext); bs, be = bs+size, be+size {
        copy(ciphertext[bs:be], fixedXOR(prevBlock, plaintext[bs:be]))
        cipher.Encrypt(ciphertext[bs:be], plaintext[bs:be])
        prevBlock = ciphertext[bs:be]
    }
    return ciphertext
}

func decryptAes128CBC(ciphertext, key, iv []byte) []byte { 
    cipher, _ := aes.NewCipher([]byte(key))
    modVal := len(ciphertext)%16
    if modVal != 0 {
        panic("This was a nasty shock!")
    }
    plaintext := make([]byte, len(ciphertext))
    size := 16
    prevBlock := iv
    //doing 'manual' application of XOR as instructed rather than using library functions (beyond 'cipher.Encrypt')
    for bs, be := 0, size; bs < len(ciphertext); bs, be = bs+size, be+size {
        cipher.Decrypt(plaintext[bs:be], ciphertext[bs:be])
        //'plaintext' is not plain text until this operation.. symmetrically with use of 'ciphertext' above
        copy(plaintext[bs:be], fixedXOR(prevBlock, plaintext[bs:be]))
        prevBlock = ciphertext[bs:be]
    }
    return plaintext
}