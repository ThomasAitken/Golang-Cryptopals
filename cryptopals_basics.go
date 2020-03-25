package main

//Things I've learnt about Go that are highly relevant to this set of tasks:
	/* • Strings are underlyingly byte slices, by default represented in Base 10 elements:
			→ If the character is in ASCII 0-255 [1-byte ASCII], then stringBytes[i] is its ASCII # in decimal 
			→ In the case of Hex strings, each byte represents precisely two characters (because Hex is 4-bit)
	   • A rune is an alias for int32 (even though they can look like chars), and since bytes function like int8, ASCII runes are essentially the same as bytes 
	   • As a result of these facts, these types are easily intertranslatable!
	*/
//

import (
	// "encoding/binary"
	"encoding/hex"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	// "bytes"
	"math"
	// "log"
)

func main() {
	var challengeNumber string = os.Args[1]
	var input string = os.Args[2]
	if challengeNumber == "1" { 
		var output string = hexTo64(input)
		fmt.Println(output)
	} else if challengeNumber == "2" {
		var secondInput string = os.Args[3]
		var output string = fixedXOR(input, secondInput)
		fmt.Println(output)
	} else if challengeNumber == "3" {
		var x string = decodeXORCipher(input)
		fmt.Println(x)
	}
	return
}

//helper
func decodeHex(input string) []byte { 
	bytes, err := hex.DecodeString(input)
	if err != nil {
		fmt.Printf("failed to decode hex: %s", err)
	}
	return bytes
}

//challenge1 main
func hexTo64(input string) string { 
	//decode string to byte slice
	bytes := decodeHex(input)
	//encode byte slice as 64
	var base64Out string = base64.StdEncoding.EncodeToString(bytes)
	return base64Out
}

//challenge2 main
func fixedXOR(firstInput string, secondInput string) string { 
	firstBytes := decodeHex(firstInput)
	secondBytes := decodeHex(secondInput)
	xorBytes := make([]byte, len(firstBytes))
	for i := 0; i < len(firstBytes); i++ {
		xorBytes[i] = firstBytes[i] ^ secondBytes[i]
	}
	var hexOut string = hex.EncodeToString(xorBytes)
	return hexOut
} 

//helper for 3,4
func getFrequencies(input string) map[byte]float64 { 
	bytes := decodeHex(input)
	frequenciesMap := make(map[byte]float64)
	var totalBytes int = len(bytes)
	for _, asciiByte := range bytes { 
		val, exists := frequenciesMap[asciiByte]
		if exists { 
			frequenciesMap[asciiByte] = val + float64(1)/float64(totalBytes)
		} else { 
			frequenciesMap[asciiByte] = float64(1)/float64(totalBytes)
		}
	}
	return frequenciesMap
}

//helper
// func averagenessScore(input string, languageFreqs map[rune]float64) float64 { 

// }

//helper for 3,4
func decipherString(input []byte, key int) []byte { 
	xorBytes := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		xorBytes[i] = input[i] ^ byte(key)
	}
	return xorBytes
}

//helper for 3,4
func sortByFrequencies(input map[byte]float64) [][]float64 { 
	//hackkeys stores slices like so: [FREQUENCY, ASCIINUM]
	//ASCIINUM is byte/int not float64 so storing it as float64 here is laziness - just saves me defining struct.. convert back later
	hackkeys := make([][]float64, len(input))
	for i := range hackkeys {
    	hackkeys[i] = make([]float64, 2)
	}
	for key, val := range input {
	   hackkeys = append(hackkeys, []float64{val, float64(key)})
	}
	// fmt.Println(hack)
	sort.Slice(hackkeys, func(i, j int) bool { return hackkeys[i][0] > hackkeys[j][0] })
	return hackkeys
}

/*measure distance of decoded text in terms of character frequencies from average Portrait of Artist text of same length by very simple method of summing the squared differences of the percentages of each character (i.e. for char 'e', it might be (10-15)^2). Those characters that exist in one text and not the other are simply ignored, under the assumption that they will not affect the results in any important way.
Since we are measuring distance from a representative probability distribution, the smaller the score the better.
*/ 
func scoreDecodedText(inputLength int, decodedFrequencies map[byte]float64, languageData map[byte]float64) float64 { 
	var score float64
	for key, val := range decodedFrequencies {

	}
}

//challenge3 main
func decodeXORCipher(input string) string {
	//Source: edited version of Portrait of Artist as a Young Man.. not a perfect source but lazy.. see io.py for ugly source code
	//turns out you can literally call runes 'bytes' and the compiler doesn't complain
	portraitOfArtistData := map[byte]float64{'P': 0.02, 'r': 4.49, 'o': 5.82, 'd': 3.87, 'u': 2.05, 'c': 1.75, 'e': 10.09, ' ': 17.23, 'b': 1.11, 'y': 1.41, 'C': 0.08, 'l': 3.55, 'h': 5.48, 'a': 6.29, 't': 6.85, '.': 0.94, 'H': 0.23, 'T': 0.25, 'M': 0.07, 'L': 0.04, 'v': 0.63, 's': 5.15, 'i': 5.23, 'n': 5.55, 'A': 0.15, 'F': 0.05, 'w': 1.8, 'f': 2.09, 'Y': 0.02, 'g': 1.66, 'J': 0.02, 'm': 1.82, 'p': 1.27, 'I': 0.16, 'V': 0.01, '"': 0.06, 'E': 0.03, 'O': 0.04, ',': 0.79, '1': 0.0, '8': 0.0, 'k': 0.66, ':': 0.13, 'B': 0.08, 'W': 0.07, 'q': 0.07, 'S': 0.13, '\'': 0.13, 'U': 0.01, 'D': 0.06, 'R': 0.02, 'K': 0.01, 'N': 0.03, '-': 0.05, 'x': 0.06, '!': 0.05, 'z': 0.03, 'j': 0.06, ';': 0.05, '?': 0.08, 'G': 0.07, 'Q': 0.0, '(': 0.0, ')': 0.0, '2': 0.0, '9': 0.0, 'Z': 0.0, 'X': 0.0, '3': 0.0, '0': 0.0, '4': 0.0, '5': 0.0, '6': 0.0, '7': 0.0}
	
	var inputFrequencies map[byte]float64 = getFrequencies(input)
	fmt.Println(inputFrequencies)
	var topCharsInput [][]float64 = sortByFrequencies(inputFrequencies)
	var topCharsGeneral [][]float64 = sortByFrequencies(portraitOfArtistData)

	var bestTextScore float64 = math.MaxFloat64
	candidateOutput := make([]byte, len(input))
	//get top 5 candidates for keys against the most frequent char in input 
	for i := 0; i < 5; i++ {
		var possKey int = int(topCharsInput[0][1]) ^ int(topCharsGeneral[i][1])
		var inputBytes []byte = decodeHex(input)
		var candidate []byte = decipherString(inputBytes, possKey)
		fmt.Println(string(candidate))
		var textScore float64 = scoreDecodedText(len(inputBytes), inputFrequencies, portraitOfArtistData)
		if textScore < bestTextScore { 
			bestTextScore = textScore
			candidateOutput = candidate
		}
		if i == 4 { 
			return candidateOutput
		}
	}
	// fmt.Println(topCharsInput)
	// fmt.Println(topCharsGeneral)
	return ""
}