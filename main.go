package main

import (
	"fmt"
	"os"
	"encoding/base64"
	"encoding/hex"
)

/* 
  USAGE: use command-line to specify set #, challenge # and any string
  arguments e.g for set 1, challenge 1: 
  ./main 1 1 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

  Challenge-specific file inputs don't need to be specified on the command-line.
*/

func main() {
	setNum := os.Args[1]
	challengeNum := os.Args[2]
	var input string
	var secondInput string
	if setNum == "1" {
		if len(os.Args) > 3 { 
			input = os.Args[3]
		}
		if len(os.Args) > 4 {
			secondInput = os.Args[4]
		}
		executeSetOne(challengeNum, input, secondInput)
	} else if setNum == "2" { 
		if len(os.Args) > 3 { 
			input = os.Args[3]
		}
		executeSetTwo(challengeNum, input)
	} else if setNum == "3" {
		if len(os.Args) > 3 { 
			input = os.Args[3]
		}
		executeSetThree(challengeNum, input)
	}
	return
}

func executeSetOne(challengeNum, input string, secondInput string) {
	if challengeNum == "1" { 
		var output string = hexTo64(input)
		fmt.Println(output)
	} else if challengeNum == "2" {
		firstBytes := decodeHex(input)
		secondBytes := decodeHex(secondInput)
		xorBytes := fixedXOR(firstBytes, secondBytes)
		var hexOut string = hex.EncodeToString(xorBytes)
		fmt.Println(hexOut)
	} else if challengeNum == "3" {
		inputBytes := decodeHex(input)
		solution := decodeXORCipher(inputBytes)
		fmt.Println(string(solution.Candidate))
		fmt.Println(solution.Score)
	} else if challengeNum == "4" {
		solution := computeMeaningfulString()
		fmt.Println(string(solution.Candidate))
		fmt.Println(solution.Score)
	} else if challengeNum == "5" {
		var input string = readSmallFile("set1_data/iceicebaby.txt")
		var output string = repeatingKeyXOR([]byte(input), "ICE", "hex")
		fmt.Println(output)
	} else if challengeNum == "6" { 
		var input string = readSmallFile("set1_data/challenge6.txt")
		fileBytes, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			panic(err)
		}
		var keySize int = probKeySize(fileBytes)
		fmt.Println(keySize)
		var transposedBytes [][]byte = transposeBytes(fileBytes, keySize) 
		// fmt.Println(transposedBytes)
		var solutionKey string
		for _, bytes := range transposedBytes {
			solution := decodeXORCipher(bytes)
			solutionKey += string(rune((solution.Key)))
		}
		fmt.Println(solutionKey)
		var output string = repeatingKeyXOR(fileBytes, solutionKey, "plain")
		fmt.Println(output)
	} else if challengeNum == "7" { 
		key := []byte("YELLOW SUBMARINE")
		var input string = readSmallFile("set1_data/challenge7.txt")
		fileBytes, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			panic(err)
		}
		var output []byte = decryptAes128ECB(fileBytes, key, false)
		fmt.Println(string(output))
	} else if challengeNum == "8" { 
		//this challenge is slightly dumb - you have to assume that the example is super contrived to expect one answer
		maxRepetitions, cipherLine, idx := identifyAesECB("set1_data/challenge8.txt")
		fmt.Printf("Line %d \"%s\" probably enciphered, repetitions: %d\n", idx, cipherLine, maxRepetitions)
	}
	return
}

func executeSetTwo(challengeNum, input string) { 
	if challengeNum == "1" {
		bytesInput := []byte(input) 
		var output []byte = padPlaintext(bytesInput, 20)
		fmt.Println(output)
	} else if challengeNum == "2" { 
		var input string = readSmallFile("set2_data/challenge10.txt")
		fileBytes, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			panic(err)
		}
		key := []byte("YELLOW SUBMARINE")
		iv := make([]byte, 16)
		var output []byte = decryptAes128CBC(fileBytes, key, iv, false)
		fmt.Println(string(output))
	} else if challengeNum == "3" { 
		output, option := randAESEncrypt([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		var mode string = identifyMode(output)
		if mode == "ECB" && option == 0 { 
			fmt.Println("True positive")
		} else if mode == "ECB" && option == 1 { 
			fmt.Println("False negative")
		} else { 
			fmt.Println("Not false negative")
		}
	} else if challengeNum == "4" { 
		var plaintext64 string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		plaintext, err := base64.StdEncoding.DecodeString(plaintext64)
		if err != nil {
			panic(err)
		}
		output := oneByteDecryption(plaintext)
		fmt.Println(string(output))
	} else if challengeNum == "5" { 
		var adminProfile map[string]string = makeMeAdmin()
		fmt.Println(adminProfile)
	} else if challengeNum == "6" { 
		fmt.Println("Reached my wit's end")
	} else if challengeNum == "7" { 
		paddedPlain := "ICE ICE BABY\x04\x04\x04\x04"
		fmt.Println(removePKCS7Pad([]byte(paddedPlain)))
		badPlain := "ICE ICE BABY\x05\x05\x05\x05"
		fmt.Println(removePKCS7Pad([]byte(badPlain)))
	} else if challengeNum == "8" { 
		output := cbcBitFlip()
		fmt.Println(string(output))
	}
	return
}

func executeSetThree(challengeNum, input string) { 
	if challengeNum == "1" { 
		output := paddingOracleAttack()
		fmt.Println(string(output))
	} else if challengeNum == "2" {
		nonce := make([]byte, 8)
		key := []byte("YELLOW SUBMARINE")
		inText, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			panic(err)
		}
		output := cryptAes128CTR(inText, key, nonce)
		inText = output
		output1 := cryptAes128CTR(inText, key, nonce)
		fmt.Println(base64.StdEncoding.EncodeToString(output1))
	}
	return
}