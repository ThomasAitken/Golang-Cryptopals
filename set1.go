package main

//Things I've learnt about Go that are highly relevant to this set of tasks:
	/* • Strings are underlyingly byte slices, by default represented in Base 10 elements:
			→ If the character is in ASCII 0-255 [1-byte ASCII], then stringBytes[i] is its ASCII # in decimal 
			→ In the case of Hex strings, each byte represents precisely two characters (because Hex is 4-bit)
	   • A rune is an alias for int32 (even though they can look like chars), and since bytes function like int8, ASCII runes are essentially the same as bytes (only more capacious). 
	   • As a result of these facts, these types are easily intertranslatable!

	   [Misc] • Python 'enumerate' is default iteration for slices, i.e. you write "for idx,thing := range {{slice}} { do stuff }"
	*/
//

//Note that it is fine and good that challenges 1-5 assume that any hex strings are of even length because they always are

import (
	"encoding/hex"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"bufio"
	"strings"
	"bytes"
	// "io"
	// "io/ioutil"
	"math"
)

type decipheredData struct {
	Candidate []byte
	Score float64
	Key int
}

func main() {
	var challengeNumber string = os.Args[1]
	var input string
	var secondInput string
	if len(os.Args) > 2 { 
		input = os.Args[2]
	}
	if len(os.Args) > 3 {
		secondInput = os.Args[3]
	}
	if challengeNumber == "1" { 
		var output string = hexTo64(input)
		fmt.Println(output)
	} else if challengeNumber == "2" {
		var output string = fixedXOR(input, secondInput)
		fmt.Println(output)
	} else if challengeNumber == "3" {
		inputBytes := decodeHex(input)
		solution := decodeXORCipher(inputBytes)
		fmt.Println(string(solution.Candidate))
		fmt.Println(solution.Score)
	} else if challengeNumber == "4" {
		solution := computeMeaningfulString()
		fmt.Println(string(solution.Candidate))
		fmt.Println(solution.Score)
	} else if challengeNumber == "5" {
		var input string = readSmallFile("iceicebaby.txt")
		var output string = repeatingKeyXOR([]byte(input), "ICE", "hex")
		fmt.Println(output)
	} else if challengeNumber == "6" { 
		var input string = readSmallFile("challenge6.txt")
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
	}
	return
}

//helper
func decodeHex(input string) []byte { 
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return nil
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

//helper for 3,4.. creates map from ASCII bytes to their frequency (as a proportion)
//takes as input not a byte slice but a string, either hex or standard string
func getFrequencies(input []byte) map[byte]float64 { 
	// bytes := decodeHex(input)
	// if bytes == nil { 
	// 	bytes = []byte(input)
	// }
	frequenciesMap := make(map[byte]float64)
	var totalBytes int = len(input)
	for _, asciiByte := range input { 
		val, exists := frequenciesMap[asciiByte]
		if exists { 
			frequenciesMap[asciiByte] = val + float64(1)/float64(totalBytes)
		} else { 
			frequenciesMap[asciiByte] = float64(1)/float64(totalBytes)
		}
	}
	return frequenciesMap
}

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

/*
  measure distance of decoded text in terms of character frequencies from average Portrait of Artist text of same length by very simple method of summing the squared differences of the percentages of each character (i.e. for char 'e', it might be (10-15)^2). 
  Since we are measuring distance from a representative probability distribution, the smaller the score the better.
*/ 
func scoreDecipheredText(decodedFrequencies map[byte]float64, languageData map[byte]float64) float64 { 
	var score float64
	for key, val := range languageData {
		_, exists := decodedFrequencies[key]
		if !exists {
			decodedFrequencies[key] = float64(0)
		}
		//decodedFrequencies vals are proportions not percentages so multiply by 100 before squaring diff
		score += math.Pow(val - 100*decodedFrequencies[key], 2)
	}
	for key, val := range decodedFrequencies { 
		_, exists := languageData[key]
		/*
		  account for strange chars that appear in texts deciphered with wrong cipher. If a weird char has high frequency in 'deciphered' string, 
		  then obviously that should push up the score! 
		*/
		if !exists {
			score += math.Pow(100*val - 0, 2)
		}
	}
	// fmt.Println(score)
	return score
}

//challenge3 main
func decodeXORCipher(input []byte) decipheredData {
	//Source: edited version of Portrait of Artist as a Young Man.. not a perfect source but lazy and sentimental.. see io.py for ugly source code
	//turns out you can literally call runes 'bytes' and the compiler doesn't complain = fun lifehack!
	portraitOfArtistData := map[byte]float64{'P': 0.02, 'r': 4.49, 'o': 5.82, 'd': 3.87, 'u': 2.05, 'c': 1.75, 'e': 10.09, ' ': 17.23, 'b': 1.11, 'y': 1.41, 'C': 0.08, 'l': 3.55, 'h': 5.48, 'a': 6.29, 't': 6.85, '.': 0.94, 'H': 0.23, 'T': 0.25, 'M': 0.07, 'L': 0.04, 'v': 0.63, 's': 5.15, 'i': 5.23, 'n': 5.55, 'A': 0.15, 'F': 0.05, 'w': 1.8, 'f': 2.09, 'Y': 0.02, 'g': 1.66, 'J': 0.02, 'm': 1.82, 'p': 1.27, 'I': 0.16, 'V': 0.01, '"': 0.06, 'E': 0.03, 'O': 0.04, ',': 0.79, '1': 0.0, '8': 0.0, 'k': 0.66, ':': 0.13, 'B': 0.08, 'W': 0.07, 'q': 0.07, 'S': 0.13, '\'': 0.13, 'U': 0.01, 'D': 0.06, 'R': 0.02, 'K': 0.01, 'N': 0.03, '-': 0.05, 'x': 0.06, '!': 0.05, 'z': 0.03, 'j': 0.06, ';': 0.05, '?': 0.08, 'G': 0.07, 'Q': 0.0, '(': 0.0, ')': 0.0, '2': 0.0, '9': 0.0, 'Z': 0.0, 'X': 0.0, '3': 0.0, '0': 0.0, '4': 0.0, '5': 0.0, '6': 0.0, '7': 0.0}
	
	var inputFrequencies map[byte]float64 = getFrequencies(input)
	// fmt.Println(inputFrequencies)
	var topCharsInput [][]float64 = sortByFrequencies(inputFrequencies)
	var topCharsGeneral [][]float64 = sortByFrequencies(portraitOfArtistData)

	var bestTextScore float64 = math.MaxFloat64
	var bestKey int
	candidateOutput := make([]byte, len(input))
	//get top 5 candidates for keys against the most frequent char in input 
	for i := 0; i < 5; i++ {
		var possKey int = int(topCharsInput[0][1]) ^ int(topCharsGeneral[i][1])
		// var inputBytes []byte = decodeHex(input)
		var candidate []byte = decipherString(input, possKey)
		// fmt.Println(string(candidate))
		var decodedFrequencies map[byte]float64 = getFrequencies(candidate)
		var textScore float64 = scoreDecipheredText(decodedFrequencies, portraitOfArtistData)
		if textScore < bestTextScore { 
			bestTextScore = textScore
			candidateOutput = candidate
			bestKey = possKey
		}
	}
	data := decipheredData{Candidate: candidateOutput, Score: bestTextScore, Key: bestKey}
	return data 
}

//challenge4 main.. piggybacks on 3
func computeMeaningfulString() decipheredData { 
	f, err := os.Open("challenge4.txt")
	if err != nil {
		panic(err)
	}
	var line string
	reader := bufio.NewReader(f)
	bestCandidate := make([]byte, 30)
	var bestScore float64 = math.MaxFloat64
	var bestKey int
	for {
        line, err = reader.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		//should say 60 for each line
		// fmt.Printf(" > Read %d characters\n", len(line))
		lineBytes := decodeHex(line)
		data := decodeXORCipher(lineBytes)
		if err != nil {
            break
		}
		if data.Score < bestScore { 
			bestScore = data.Score
			bestCandidate = data.Candidate
			bestKey = data.Key
		}
    }
	return decipheredData{Candidate: bestCandidate, Score: bestScore, Key: bestKey} 
}

//returns long string
func readSmallFile(filename string) string { 
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(f)
	var input string
	var line string
	for {
		line, err = reader.ReadString('\n')
		input += line
		// line = strings.TrimSuffix(line, "\n")
		if err != nil {
			break
		}
		// fmt.Println(input)
	}
	return input
}

//challenge5 main and used in challenge6
func repeatingKeyXOR(input []byte, key string, outputMode string) string { 
	output := make([]byte, len(input))
	var keyIdx int
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[keyIdx]
		if keyIdx < len(key)-1 { 
			keyIdx ++
		} else { 
			keyIdx = 0
		}
	}
	if outputMode == "hex" {
		return hex.EncodeToString(output)
	} 
	return string(output)
}

//challenge6 helper
func hammingDistance(bytes1, bytes2 []byte) uint32 { 
	switch bytes.Compare(bytes1, bytes2) {
		case 0: // len(bytes1) == len(bytes2)
		case 1: // len(bytes1) > len(bytes2)
			temp := make([]byte, len(bytes1))
			copy(temp, bytes2)
			bytes2 = temp
		case -1: // len(bytes1) < len(bytes2)
			temp := make([]byte, len(bytes2))
			copy(temp, bytes1)
			bytes1 = temp
		}

//EXPLANATION OF BELOW:
	/*
		Recall: XOR(bit1, bit2) returns 1 for pairs {(1,0),(0,1)}, 0 otherwise
		Idea: count bit diffs b/w two strings by XORing each bit pair.
		Problem: in this language, we can only directly apply XOR to bytes! 
		Solution: 
			Some algorithm for counting 1s in XOR-byte.
			Below uses Brian Kernighan's ultra-cool trick for counting 1s in bit-string: 
			https://www.geeksforgeeks.org/count-set-bits-in-an-integer/ 
	*/
//
	var distance uint32
	for i := 0; i < len(bytes1); i++ {
		var xor byte = bytes1[i] ^ bytes2[i]
		for mutByte := xor; mutByte > 0; mutByte = mutByte&(mutByte-1)  {
			distance ++
		}
	}
	return distance
}
/*
  Extra note: it took me a few minutes to grok Brian Kernighan's algorithm for set-bit counting (GeeksforGeeks explanation is imperfect) so I'll explain here:
	(i) Observe: decrementing in fixed-length binary preserves all 1s and 0s moving from l-r until the rightmost 1; 
		that 1 is zeroed (& if more 0s to the right, the first is set to 1) [e.g. 01 - 01 = 00 or 10 - 01 = 01]
	(ii) So: the bitwise conjunction n&(n-1) will have n-1 # of 1s, because it just zeroes the rightmost 1 from n [e.g. 110&101 = 100]
	(iii) So if we assign a variable x to be n and repeatedly assign x := n&(n-1), it will reach 0 with # assignments = # 1s in original string!
	
	This is insanely elegant with optimal time-complexity = O(log m) [with m the dec representation of the binary # n]
	(Equivalently, where m is the length of the binary string, O(m).)
*/


//helper to probKeySize
//EXPLANATION: 
	/*
	  Conceptual: 
	  	The more often the same bytes appear in the same position in equally split blocks of size x, the more likely it is that x is the size of the key.
		Why? Because English plaintext has lots of repeated characters - much more repetition than a random 0-255 string.
		Hence we need to find the size x that correlates with the most sameness between blocks
	  Implementation:
		I decided to do it more rigorously than Cryptopals suggested because I initially did it unrigorously and this caused me to believe that something had gone badly wrong - but it hadn't.
		I create 10 blocks of size x and get the average of all possible pairwise Hamming Distance calculations (45 in total).
		I average these and normalise as per the instructions. 
	*/
//
func getHammingAve(fileBytes []byte, possKeySize int) float64 { 
	byteBlocks := make([][]byte, 10)
	var factor int
	var hammingSum uint32

	var testcount int
	for i := 0; i < 10; i++ {
		byteBlocks[i] = fileBytes[possKeySize*factor:possKeySize*(factor+1)]
		factor ++
		if i != 0 {
			for j := i-1; j >= 0; j -- { 
				// fmt.Println(j)
				hammingDist := hammingDistance(byteBlocks[i], byteBlocks[j])
				hammingSum += hammingDist
				testcount ++
			}	
		}
	}
	// average normalised by keysize
	var hammingAve float64 = float64(hammingSum)/(45.0*float64(possKeySize))
	return hammingAve
}

//challenge6 helper
func probKeySize(fileBytes []byte) int { 
	var bestKeySize int
	var minHammingAve float64 = math.MaxFloat64
	for i := 2; i < 41; i ++ { 
		var hammingAve float64 = getHammingAve(fileBytes, i)
		// fmt.Println(hammingAve, i)
		if hammingAve < minHammingAve { 
			minHammingAve = hammingAve
			bestKeySize = i
		}
	}
	return bestKeySize
}

//challenge6 helper
func transposeBytes(fileBytes []byte, keySize int) [][]byte {
	transposedBytes := make([][]byte, keySize)
	for i := 0; i < keySize; i++ {
		bytesIdx := i
		for bytesIdx + keySize < len(fileBytes)-1 { 
			transposedBytes[i] = append(transposedBytes[i], fileBytes[bytesIdx])
			bytesIdx += keySize
		} 
	}
	return transposedBytes
}
