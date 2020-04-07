package main

import (
	// "encoding/hex"
	// "encoding/base64"
	"fmt"
	// "os"
	// "sort"
	// "bufio"
	// "strings"
	// "bytes"
    "math/rand"
    "time"
    "crypto/aes"
    random "crypto/rand"
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

  There have been several confusing sentences like this so far in these
  challenges. I wish they were less cryptic with their instructions and
  exposition. It has caused me to waste some time. And my time is precious
  goddamnit!

  Also I'm mad at these fuckers for not telling me that the 10.txt is base64
  encoded after the AES encryption.. EXTREMELY MAD. Maybe it should have been
  obvious... but nah
*/

//helper
func addPKCS7Pad(plaintext []byte) []byte { 
    modVal := len(plaintext)%16
    padding := make([]byte, 16-modVal)
    for i := 0; i < len(padding); i ++ {
        padding[i] = byte(len(padding))
    }
    plaintext = append(plaintext, padding...)
    return plaintext
}

//helper: validates padding then removes
func removePKCS7Pad(plaintext []byte) []byte {
    finIdx := len(plaintext)-1 
    finValue := int(plaintext[finIdx])
    //validate padding
    for i := finIdx; i >= finIdx-finValue; i -- { 
        if int(plaintext[i]) != finValue { 
            panic("Decryption failed!")
        } 
    }
    plaintext = plaintext[:len(plaintext)-finValue]
    return plaintext
}

func encryptAes128ECB(plaintext, key []byte) []byte { 
    cipher, _ := aes.NewCipher([]byte(key))
    plaintext = addPKCS7Pad(plaintext)
    ciphertext := make([]byte, len(plaintext))
    size := 16
    for bs, be := 0, size; bs < len(plaintext); bs, be = bs+size, be+size {
        cipher.Encrypt(ciphertext[bs:be], plaintext[bs:be])
    }
    return ciphertext
}

func encryptAes128CBC(plaintext, key, iv []byte) []byte {
    cipher, _ := aes.NewCipher([]byte(key))
    plaintext = addPKCS7Pad(plaintext)
    ciphertext := make([]byte, len(plaintext))
    size := 16
    prevBlock := iv
    //doing 'manual' application of XOR as instructed rather than using library functions (beyond 'cipher.Encrypt')
    for bs, be := 0, size; bs < len(plaintext); bs, be = bs+size, be+size {
        copy(ciphertext[bs:be], fixedXOR(prevBlock, plaintext[bs:be]))
        cipher.Encrypt(ciphertext[bs:be], ciphertext[bs:be])
        prevBlock = ciphertext[bs:be]
    }
    return ciphertext
}

func decryptAes128CBC(ciphertext, key, iv []byte, padding bool) []byte { 
    cipher, _ := aes.NewCipher([]byte(key))
    plaintext := make([]byte, len(ciphertext))
    size := 16
    prevBlock := iv
    //doing 'manual' application of XOR as instructed rather than using library functions (beyond 'cipher.Decrypt')
    for bs, be := 0, size; bs < len(ciphertext); bs, be = bs+size, be+size {
        cipher.Decrypt(plaintext[bs:be], ciphertext[bs:be])
        //'plaintext' is not plain text until this operation.. symmetrically with use of 'ciphertext' above
        copy(plaintext[bs:be], fixedXOR(prevBlock, plaintext[bs:be]))
        prevBlock = ciphertext[bs:be]
    }
    if padding == true {
        plaintext = removePKCS7Pad(plaintext)
    }
    return plaintext
}

/*
  Here these Cryptopals once more engage in heinous ambiguity. Completely
  heinous. This is far worse than anything that has come before; I literally had
  no clue what was being asked of me before I looked at how other people had
  interpreted this problem online. I thought they were asking me to feed the
  oracle just any old plaintext input and find a way to determine on the basis
  of the ciphertext alone whether the text was enciphered using ECB or CBC. (And
  not just determine with high confidence either; the language ("detect [...]
  each time" suggested to me a fully deterministic solution.) But my thinking
  was that unless there was some info I was missing, there is no way to
  determine this with a high hit rate (let alone deterministically) unless the
  plaintext inputs always contain strong regularities and are big. (The only
  relevant strat we have been taught hitherto that could bear on this is looking
  for repeated 16-byte blocks in the ciphertext - a telltale sign of ECB but not
  likely to organically make itself known in a short text). Even assuming this
  interpretation of the task, I was further confused by the stipulation that the
  encryption function (incidentally, why did they call this an
  'encryption_oracle' in the embedded code signature???????????) should have
  randomly appended bytes attached to the beginning and to the end. 'What is the
  meaning of this?,' I thought to myself. 'They want me to exploit padding info
  somehow??' So I began to think I was supposed to use a technique beyond
  basic-bitch ECB detection via repeated blocks, which thereby sent me on a path
  to thinking that I was perhaps meant to implement this:
  https://en.wikipedia.org/wiki/Padding_oracle_attack. To make matters worse,
  the sentence mentioning the appendage of bytes to the beginning and end of the
  plaintext is also ambiguous as to whether there is one or two instances of
  random selection: "Under the hood, have the function append 5-10 bytes (count
  chosen randomly) before the plaintext and 5-10 bytes after the plaintext"). I
  began to tear my hair out.

  It was only by looking at a couple of other people's approach to this task
  that I discovered that others decided that the task is just asking for
  basic-bitch ECB detection and that they're not really expecting you to create
  anything very useful or robust. And I guess the logic of the random bytes at
  the beginning and the end is just to slightly fuck you over... (But like
  wtf?). The two people's code I looked at just tested their detection oracle on
  plaintext which consisted entirely of the same character!!! So yeah. Good
  effort, SOHKBqM0TOUK/XEzTC9m9A==!

  ... Curious to see if you can actually detect ECB-mode on normal English
  plaintext, I decided to see if some of the early few pages from Portrait of
  the Artist contained any repeated 16-byte blocks. Turns out the extract I
  chose did not. Which confirmed my suspicion that this is a pretty weak power I
  have, and that this challenge is silly.
*/

func randBytes(size int) []byte { 
    output := make([]byte,size)
    _, err := random.Read(output)
	if err != nil {
        panic(err)
	}
    return output
}

func addRandBytes(plaintext []byte, start, end int) []byte { 
    rand.Seed(time.Now().UnixNano())
    n := rand.Intn(end-start)+start
    m := rand.Intn(end-start)+start

    newPlaintext := make([]byte, len(plaintext)+n+m)
    startRand := randBytes(n)
    endRand := randBytes(m)
    plaintext = append(plaintext, endRand...)
    newPlaintext = append(startRand, plaintext...)
    fmt.Println("plaintext", newPlaintext)
    return newPlaintext
}

func randAESEncrypt(plaintext []byte) ([]byte, int) { 
    key := randBytes(16)
    fmt.Println("key", key)
    // //I know it's stupid but that's what they wanted me to do..
    iv := randBytes(16)
    fmt.Println("iv", iv)
    messyPlaintext := addRandBytes(plaintext, 5, 11)
    rand.Seed(time.Now().UnixNano())
    option := rand.Intn(2)
    ciphertext := make([]byte, len(messyPlaintext))
    fmt.Println(option)
    if option == 0 { 
        ciphertext = encryptAes128ECB(messyPlaintext, key)
        fmt.Println(ciphertext)
    } else { 
        ciphertext = encryptAes128CBC(messyPlaintext, key, iv)
        fmt.Println(ciphertext)
    }
    return ciphertext, option
}

func identifyMode(ciphertext []byte) string { 
    var uniqueBlocks [][]byte
    var repeatCount int
    for bs, be := 0, 16; be < len(ciphertext); bs, be = bs+16, be+16 {
        block := ciphertext[bs:be]
        if contains(uniqueBlocks, block) {
            repeatCount++
        } else { 
            uniqueBlocks = append(uniqueBlocks, block)
        }
    }
    if repeatCount > 0 { 
        return "ECB"
    }
    return "Undetermined"
}