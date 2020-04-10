package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"math/rand"
	"time"
)

var key []byte
func encryptLine(optionalInput string) ([]byte, []byte) { 
	var plaintext string
	if optionalInput == "" {
		content, err := ioutil.ReadFile("set3_data/challenge1.txt")
		if err != nil {
			//Do something
		}
		lines := strings.Split(string(content), "\n")
		rand.Seed(time.Now().Unix())
		plaintext = lines[rand.Intn(len(lines))]
		fmt.Println(plaintext)
		fmt.Println(len(plaintext))
	} else {
		plaintext = optionalInput
	}
	iv := randBytes(16)
	ciphertext := encryptAes128CBC([]byte(plaintext), key, iv)
	return ciphertext, iv
}

func checkLine(ciphertext, iv []byte) bool { 
	plaintext := decryptAes128CBC(ciphertext, key, iv, true)
	//padding failed
	if plaintext == nil { 
		return false
	} 
	return true
}

func testFunctions() {
	iv := randBytes(16)
	ciphertext1 := []byte("helloworldiamtom")
	verdict1 := checkLine(ciphertext1, iv)
	fmt.Println(verdict1)
}

/* WIKI explanation of this attack is quite badly written/misleading so here's
  my attempt:

  Necessary conditions: 
      This attack assumes the quite strange - but apparently
      occasionally realistic - scenario, where you have access to two things:
      (a) a ciphertext (ideally including the IV, which apparently
      sometimes/often forms the start of the ciphertext), and (b) a "padding
      oracle". This oracle does the following: if you feed it a couple of
      cipherblocks, it gives you back info about whether the padding of the
      second of these blocks is correct (it assumes that the second block is the
      final block of a text). To do this, this padding oracle actually has to
      decrypt the second block, because padding can only be assessed on
      plaintext.

  Attack Description/Explanation: 
	  Suppose you randomly modify the last digit of ciphertext block C_1 to make 
	  C_1' & then feed (C_1', C_2) to the oracle, which then tells you that the padding 
	  is valid. This strongly suggests that the pseudo-plaintext P_2' on which the 
	  oracle made the evaluation (i.e. C_1' ^ D(C_2)) happened to terminate in 
	  \x01 (yes, it could be that you've created a text P_2' terminating with \x02\x02 
	  but that requires that the penultimate character of the real P_2 happened to 
	  be \x02 and that you didn't hit \x02\x01 first while feeding in modified blocks). 

    So this simple boolean verdict about padding has given you the following:
		D(C_2) ^ C_1' terminates with \x01 
		=> D(C_2)[15] = C_1'[15] ^ \x01

	This can be generalised to find other characters in D(C_2) as follows: 
		Let n be the # of characters from the end of the block of the character you
        seek (i.e. if you wanted to find the first character of the block, n=16)

        (i) Moving from the back of the block, find the modification of C_1 s.t. 
        D(C_2) ^ C_1' terminates with \x[n].
        (ii) When you've done this n times, you now have D(C_2)[16-n] = C_1'[16-n] ^ \x[n] 

    After 16 iterations, you have the entire block D(C_2), from which you can
	calculate C_2 = D(C_2) ^ C_1
	
*/

func paddingOracleAttack() []byte { 
	key = randBytes(16)
	ciphertext, iv := encryptLine("")
	plaintext := make([]byte, len(ciphertext))
	// C_1, C_1'
	prevblock := iv
	prevblockMut := make([]byte,len(prevblock))
	copy(prevblockMut, prevblock)
	//block iteration
	for bs, be := 0, 16; bs < len(ciphertext); bs, be = bs+16, be+16 {
		var decryptedBlock [16]byte
		cipherblock := ciphertext[bs:be]
		//character iteration
		for blockIdx := 15; blockIdx >= 0; blockIdx -- { 
			XORtarget := 16-blockIdx
			var hackedVal byte
			/*filling out prevblock with appropriate values to lay ground for padding validation
				i.e. suppose XORtarget is \x02, then we're changing C_1'[14],[15] with values s.t. P_2'[14], 
				[15] = \x02. Such values determined by XORing against previous char decryptions.
			*/
			for j := XORtarget-1; j >= 1; j -- {
				prevblockMut[16-j] = decryptedBlock[16-j] ^ byte(XORtarget)
			}
			for ascii := 0; ascii < 256; ascii ++ {
				prevblockMut[blockIdx] = byte(ascii)
				if checkLine(cipherblock, prevblockMut) == true { 
					//hackedVal = D(C_2)[n]
					hackedVal = byte(ascii) ^ byte(XORtarget)
					break
				}
			}
			decryptedBlock[blockIdx] = hackedVal
			plaintext[bs+blockIdx] = hackedVal^prevblock[blockIdx]
		}
		prevblock = cipherblock
		copy(prevblockMut, cipherblock)
	}
	plaintext = removePKCS7Pad(plaintext)
	return plaintext
}	