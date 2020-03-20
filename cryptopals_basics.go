package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/base64"
	"fmt"
	"os"
	// "math"
	// "log"
)

func main() {
	var challengeNumber string = os.Args[1]
	var input string = os.Args[2]
	if challengeNumber == "1" { 
		var output string = hexTo64(input)
		fmt.Println(output)
	}
	if challengeNumber == "2" {
		var secondInput string = os.Args[3]
		var output string = fixedXOR(input, secondInput)
		fmt.Println(output)
	}
	return
}

func decodeHex(input string) []byte { 
	bytes, err := hex.DecodeString(input)
	if err != nil {
		fmt.Printf("failed to decode hex: %s", err)
	}
	return bytes
}


func hexTo64(input string) string { 
	//decode string to byte slice
	bytes := decodeHex(input)
	//encode byte slice as 64
	var base64Out string = base64.StdEncoding.EncodeToString(bytes)
	return base64Out
}

func fixedXOR(firstInput string, secondInput string) string { 
	firstBytes := decodeHex(firstInput)
	secondBytes := decodeHex(secondInput)
	buf := bytes.NewBuffer(firstBytes)
	for i := 0; i < len(firstBytes); i++ {
		myfirstint, err := binary.ReadVarint(firstBytes[i])
		anotherint, err := binary.ReadVarint(secondBytes[i])
	}
}