package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"strings"
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

  Necessary conditions: This attack assumes the quite strange - but apparently
      occasionally realistic - scenario, where you have access to two things:
      (a) a ciphertext (ideally including the IV, which apparently
      sometimes/often forms the start of the ciphertext), and (b) a "padding
      oracle". This oracle does the following: if you feed it a couple of
      cipherblocks, it gives you back info about whether the padding of the
      second of these blocks is correct (it assumes that the second block is the
      final block of a text). To do this, this padding oracle actually has to
      decrypt the second block, because padding can only be assessed on
      plaintext.

  Attack Description/Explanation: Suppose you randomly modify the last digit of
      ciphertext block C_1 to make C_1' & then feed (C_1', C_2) to the oracle,
      which then tells you that the padding is valid. This strongly suggests
      that the pseudo-plaintext P_2' on which the oracle made the evaluation
      (i.e. C_1' ^ D(C_2)) happened to terminate in \x01 (yes, it could be that
      you've created a text P_2' terminating with \x02\x02 but that requires
      that the penultimate character of the real P_2 happened to be \x02 and
      that you didn't hit \x02\x01 first while feeding in modified blocks).

    So this simple boolean verdict about padding has given you the following:
		D(C_2) ^ C_1' terminates with \x01
		=> D(C_2)[15] = C_1'[15] ^ \x01

	This can be generalised to find other characters in D(C_2) as follows:

		For curr_index = 15; decrementing:
			(i) For i= 15 to i=curr_index+1:
					edit C_1'[i] s.t. P_2'[i] = XORtarget (\x02, \x03, etc)
					using previously decrypted values, i.e.  C_1'[i] =
					decryptedBlock[i] ^ XORtarget
			(ii) Now iterate over acsiis until you find the ascii s.t.
			C_1'[curr_index]^C_2[curr_index] = XORtarget. Then the plaintext
			val is ascii ^ XORtarget ^ C_1[15]
			(iii) Store ascii ^ XORtarget in decryptedBlock & plaintext in plaintext buffer

    After 16 iterations, you have filled the corresponding plaintext block.


    Initially, I implemented this attack imperfectly, so that it was fucking up
	the last block around half of the time. This was because the padding in the
	final block increases the likelihood of circumstantial padding-validity
	dramatically. My code had asumed that if I insert, say, \x10 into C_1'[15],
	then when I send C_1', C_2 off the oracle and get a positive response, that
	means D(C_2)[15] = C_1'[15] ^ \x01. But it could be that D(C_2)[15] =
	C_1'[15] ^ \xn if P_2 ends with \xn\xn\xn\xn...

	I got around this problem as follows:
		If in last block having selected C_1'[15] s.t. oracle verdict is "valid":
			If C_1'[15] == C_1[15]:
				Modify C_1'[14] then send (C_1',C_2) to oracle.
				If you still get valid padding:
					P_2 must be padded with \x01. So proceed as usual.
				Else:
					P_2 has extra padding & you haven't yet found C_1'[15]
					s.t. C_1'[15]^D(C_2)[15] = \x01. So keep looking for this.


	So now this is a fully rigorous implementation. The chance of a fail is very low.
*/

func paddingOracleAttack() []byte {
	key = randBytes(16)
	ciphertext, iv := encryptLine("")
	plaintext := make([]byte, len(ciphertext))
	// C_1, C_1'
	prevblock := iv
	prevblockMut := make([]byte, len(prevblock))
	copy(prevblockMut, prevblock)
	//block iteration
	for bs, be := 0, 16; bs < len(ciphertext); bs, be = bs+16, be+16 {
		var decryptedBlock [16]byte
		cipherblock := ciphertext[bs:be]
		//character iteration
		for blockIdx := 15; blockIdx >= 0; blockIdx-- {
			XORtarget := 16 - blockIdx
			var hackedVal byte
			/*filling out prevblock with appropriate values to lay ground for padding validation
			i.e. suppose XORtarget is \x02, then we're changing C_1'[14],[15] with values s.t. P_2'[14],
			[15] = \x02. Such values determined by XORing against previous char decryptions.
			*/
			for j := XORtarget - 1; j >= 1; j-- {
				prevblockMut[16-j] = decryptedBlock[16-j] ^ byte(XORtarget)
			}
			for ascii := 0; ascii < 256; ascii++ {
				prevblockMut[blockIdx] = byte(ascii)
				if checkLine(cipherblock, prevblockMut) == true {
					//hackedVal = D(C_2)[n]
					hackedVal = byte(ascii) ^ byte(XORtarget)
					//mad hackz... explainer above
					if bs+16 == len(ciphertext) {
						if blockIdx == 15 && prevblockMut[blockIdx] == prevblock[blockIdx] {
							prevblockMut[14] = prevblockMut[14] + 1
							//padding doesn't organically terminate with 1
							if checkLine(cipherblock, prevblockMut) == false {
								continue
							}
						}
					}
					break
				}
			}
			decryptedBlock[blockIdx] = hackedVal
			plaintext[bs+blockIdx] = hackedVal ^ prevblock[blockIdx]
		}
		prevblock = cipherblock
		copy(prevblockMut, cipherblock)
	}
	fmt.Println(plaintext)
	plaintext = removePKCS7Pad(plaintext)
	return plaintext
}

//challenge 2
func cryptAes128CTR(inText, key, nonce []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	counter := make([]byte, 8)
	outText := make([]byte, len(inText))
	for bs, be := 0, 16; bs < len(inText); bs, be = bs+16, be+16 {
		nAndC := append(nonce, counter...)
		keystream := make([]byte, 16)
		cipher.Encrypt(keystream, nAndC)
		if be > len(inText) {
			be = len(inText)
		}
		copy(outText[bs:be], fixedXOR(inText[bs:be], keystream[:be-bs]))
		counter[0] = counter[0] + 1
	}
	return outText
}

/*
  Challenge explanation:

  CTR encryption involves the XORing of a plaintext block with the encrypted
  block consisting of the 'nonce' and the 'counter' (the 'keystream'). So we
  have ciphertext = plaintext ^ keystream and keystream = plaintext ^
  ciphertext. If you have lots of cipherblocks and you know they're all
  encrypted with the same keystream, then statistical methods become available
  to crack the keystream, and therefore crack all the cipherblocks. The key
  things to look out for are solos, duos and trios of bytes that occur in the
  same spot across multiple cipherblocks. If the keystream is the same every
  time and they're in the same spot, they must be produced by the same
  plaintext! So they most likely correspond to frequent characters, digrams and
  trigrams in English, and you can therefore guess at the keystream bytes that
  are producing them by XORing these English-language options against the
  cipherbytes (and then observing the ramifications for the plaintext characters
  in the other rows for that/those column/s).


  My algorithm looks at the top 60 English-language possibilities for
  single-character columnwise repetitions, works out what are the ramifications
  for the other rows and picks the candidate that leads to the most
  English-looking distribution of characters for the other columns. I thought I
  would need duograms and trigrams but it turns out that they are not required.

  ... Well, they are required to correctly finish off the longer lines, which
  are utterly impossible to do with this 0 look-ahead (& 0 look-behind) method
  because of the absence or attenuation of the columnwise comparisons. But I
  will not be adding this sophistication to my algorithm because that would be
  pretty complicated and this took enough time as it is - a lot of confused
  debugging!.
*/

//challenge 3 nonsense
var unigrams = map[byte]float64{'P': 0.02, 'r': 4.49, 'o': 5.82, 'd': 3.87, 'u': 2.05, 'c': 1.75,
	'e': 10.09, ' ': 17.23, 'b': 1.11, 'y': 1.41, 'C': 0.08, 'l': 3.55, 'h': 5.48, 'a': 6.29, 't': 6.85, '.': 0.94,
	'H': 0.23, 'T': 0.25, 'M': 0.07, 'L': 0.04, 'v': 0.63, 's': 5.15, 'i': 5.23, 'n': 5.55, 'A': 0.15, 'F': 0.05,
	'w': 1.8, 'f': 2.09, 'Y': 0.02, 'g': 1.66, 'J': 0.02, 'm': 1.82, 'p': 1.27, 'I': 0.16, 'V': 0.01, '"': 0.06,
	'E': 0.03, 'O': 0.04, ',': 0.79, '1': 0.0, '8': 0.0, 'k': 0.66, ':': 0.13, 'B': 0.08, 'W': 0.07, 'q': 0.07,
	'S': 0.13, '\'': 0.13, 'U': 0.01, 'D': 0.06, 'R': 0.02, 'K': 0.01, 'N': 0.03, '-': 0.05, 'x': 0.06, '!': 0.05,
	'z': 0.03, 'j': 0.06, ';': 0.05, '?': 0.08, 'G': 0.07, 'Q': 0.0, '(': 0.0, ')': 0.0, '2': 0.0, '9': 0.0, 'Z': 0.0,
	'X': 0.0, '3': 0.0, '0': 0.0, '4': 0.0, '5': 0.0, '6': 0.0, '7': 0.0}

// var duograms = map[string]float64{"ro": 0.43, "od": 0.17, "du": 0.03, "uc": 0.05, "ce": 0.32, "ed": 0.86, "d ": 2.19, " b": 0.74, "by": 0.1, "y ": 0.79, " C": 0.05, "Co": 0.01, "ol": 0.21, "l ": 0.4, "Ch": 0.02, "ho": 0.31, "oa": 0.06, "at": 0.73, "t.": 0.09, ". ": 0.62, "  ": 0.12, " H": 0.16, " v": 0.11, "ve": 0.43, "er": 1.18, "rs": 0.22, "si": 0.27, "io": 0.17, "on": 0.68, "n ": 1.19, " A": 0.11, "Al": 0.01, "Ha": 0.01, "ai": 0.31, "in": 1.56, "ne": 0.43, "es": 0.66, "s.": 0.16, " F": 0.04, "ur": 0.31, "rt": 0.16, "th": 2.4, "he": 2.69, "r ": 0.88, " c": 0.58, "co": 0.31, "or": 0.63, "rr": 0.08, "re": 0.96, "ec": 0.16, "ct": 0.1, "ti": 0.35, "ns": 0.19, "s\n": 0.14, " M": 0.05, "en": 0.87, "nn": 0.05, "no": 0.25, "o ": 0.61, " d": 0.43, "de": 0.39, "e ": 3.2, " L": 0.03, "Le": 0.01, "ee": 0.27, "w.": 0.01, ".\n": 0.3, "A ": 0.04, " P": 0.02, "tr": 0.19, "ra": 0.31, "it": 0.59, "t ": 1.44, " o": 1.21, "of": 0.8, "f ": 0.76, " t": 2.61, "Ar": 0.01, "is": 0.79, "st": 0.63, " a": 1.9, "as": 0.63, "s ": 1.79, "a ": 0.38, " Y": 0.02, "Yo": 0.01, "ou": 0.77, "un": 0.24, "ng": 0.79, "g ": 0.54, "Ma": 0.02, "an": 1.41, "n\n": 0.09, "y\n": 0.05, "am": 0.18, "me": 0.42, " J": 0.01, "Jo": 0.01, "oy": 0.04, "e\n": 0.26, "ha": 0.75, "ap": 0.11, "pt": 0.03, "te": 0.6, " I": 0.14, " V": 0.01, " i": 0.77, "ig": 0.17, "gn": 0.02, "ot": 0.26, "ta": 0.21, "ni": 0.18, "im": 0.32, "mu": 0.07, "um": 0.07, "m ": 0.34, "di": 0.2, "mi": 0.16, "tt": 0.11, "ar": 0.57, ".\"": 0.01, "\"\n": 0.01, "vi": 0.09, "id": 0.22, "d,": 0.1, ", ": 0.72, "et": 0.23, "mo": 0.19, "rp": 0.01, "ph": 0.1, "os": 0.13, "se": 0.54, "s,": 0.13, "On": 0.02, "nc": 0.16, " u": 0.18, "up": 0.11, "po": 0.14, "nd": 1.19, "ry": 0.14, " g": 0.26, "go": 0.08, "oo": 0.24, " w": 1.1, "wa": 0.46, " m": 0.45, "oc": 0.05, "ow": 0.33, "w ": 0.15, "om": 0.32, "g\n": 0.04, "do": 0.13, "wn": 0.08, "al": 0.44, "lo": 0.34, " r": 0.3, "ad": 0.4, "hi": 0.91, "d\n": 0.16, " n": 0.28, "ic": 0.27, " l": 0.47, "li": 0.41, "tl": 0.11, "le": 0.58, "bo": 0.16, "na": 0.1, "ba": 0.08, "ab": 0.1, "tu": 0.13, "ck": 0.14, "o.": 0.01, "..": 0.01, "Hi": 0.04, " f": 0.75, "fa": 0.16, "to": 0.68, "ld": 0.26, " h": 1.5, " s": 1.18, "y:": 0.01, ": ": 0.06, "ok": 0.09, "ke": 0.23, "hr": 0.08, "ug": 0.12, "gh": 0.22, "h ": 0.39, "a\n": 0.04, "gl": 0.07, "la": 0.27, "ss": 0.25, "s:": 0.01, "ir": 0.25, "ac": 0.22, "e.": 0.15, "He": 0.16, " T": 0.17, "Th": 0.21, "ca": 0.2, "wh": 0.27, " B": 0.06, "Be": 0.01, "ty": 0.08, "rn": 0.12, "iv": 0.09, "d:": 0.04, "sh": 0.22, "so": 0.23, "em": 0.22, " p": 0.46, "pl": 0.11, " O": 0.04, "wi": 0.26, "il": 0.29, "bl": 0.13, "ms": 0.06, "gr": 0.12, "sa": 0.18, "g.": 0.03, "wo": 0.19, "h.": 0.02, "Wh": 0.04, " y": 0.13, "yo": 0.13, "u ": 0.08, "we": 0.24, "be": 0.37, "fi": 0.14, "rm": 0.07, "ge": 0.2, "ts": 0.16, "d.": 0.09, "r\n": 0.06, "pu": 0.04, "ut": 0.27, "oi": 0.09, "ls": 0.08, " q": 0.04, "qu": 0.07, "ue": 0.06, "sm": 0.05, "el": 0.42, "ll": 0.47, "l.": 0.04, "r.": 0.07, " S": 0.09, "Sh": 0.01, "ay": 0.2, "ye": 0.1, "pi": 0.08, "ia": 0.05, "o\n": 0.04, "r'": 0.02, "'s": 0.1, "ip": 0.04, "pe": 0.21, "fo": 0.26, "da": 0.13, ":\n": 0.08, ",\n": 0.07, "dd": 0.04, "dy": 0.05, "y,": 0.06, "cl": 0.09, "rl": 0.06, " D": 0.05, "Da": 0.02, "nt": 0.45, "pp": 0.05, "ey": 0.18, "bu": 0.08, "tw": 0.04, "br": 0.1, "ru": 0.07, "us": 0.23, "pr": 0.17, "ma": 0.23, "lv": 0.02, "t\n": 0.09, "k ": 0.17, "Mi": 0.01, "ch": 0.31, "ae": 0.01, "av": 0.11, "k\n": 0.01, "Pa": 0.01, "ga": 0.12, " e": 0.29, "ev": 0.13, "ht": 0.15, "ie": 0.2, "su": 0.11, "pa": 0.16, "nu": 0.02, "mb": 0.07, "n.": 0.07, "if": 0.11, "ff": 0.06, "fe": 0.22, " E": 0.02, "n'": 0.04, " W": 0.06, "p\n": 0.01, "ul": 0.26, "og": 0.03, "gi": 0.08, "e,": 0.11, "ds": 0.11, "sw": 0.04, "ys": 0.06, "ef": 0.09, "rg": 0.03, "cr": 0.1, "ri": 0.37, "ly": 0.29, "af": 0.04, "ft": 0.08, "hu": 0.05, "ud": 0.08, "ea": 0.54, "sy": 0.02, "rb": 0.01, "b ": 0.01, "fl": 0.08, "ew": 0.06, "ik": 0.07, "vy": 0.01, "bi": 0.04, "rd": 0.16, " k": 0.07, "ep": 0.15, "fr": 0.17, "t,": 0.08, "h\n": 0.03, "ei": 0.11, "lt": 0.07, "l\n": 0.03, "ak": 0.08, "y.": 0.07, " R": 0.01, "Ro": 0.01, "t:": 0.01, "ws": 0.03, " N": 0.02, "Na": 0.01, "nk": 0.05, "k.": 0.02, "mp": 0.09, "Fr": 0.01, "e-": 0.01, "An": 0.04, "sk": 0.05, "St": 0.08, "De": 0.02, "lu": 0.07, "ki": 0.08, "Bu": 0.04, "ui": 0.06, "Ca": 0.01, "e'": 0.01, "oe": 0.02, "p ": 0.08, "lf": 0.06, "f.": 0.01, "ex": 0.04, "xp": 0.01, "sp": 0.1, "eg": 0.05, "! ": 0.03, "ub": 0.03, "ny": 0.05, "yt": 0.01, "wr": 0.03, "r,": 0.05, "ze": 0.01, "dr": 0.07, "au": 0.08, "sc": 0.07, "mm": 0.03, "ag": 0.14, "rf": 0.01, "fu": 0.06, "gs": 0.03, "gg": 0.02, "bb": 0.01, "La": 0.01, "aw": 0.08, "dg": 0.02, "op": 0.06, "It": 0.05, "So": 0.01, "ix": 0.01, "ky": 0.01, "rk": 0.06, "ks": 0.02, "s'": 0.01, "sl": 0.06, "m\n": 0.02, "Pe": 0.01, "rh": 0.01, "ps": 0.05, "Do": 0.01, "nw": 0.01, "Bo": 0.01, "nl": 0.06, "m.": 0.04, "my": 0.04, "xt": 0.01, "We": 0.01, "sq": 0.01, "ua": 0.04, "tc": 0.03, "sn": 0.01, "uf": 0.02, "ox": 0.01, "Ho": 0.02, "n!": 0.01, " j": 0.04, "ju": 0.02, "cu": 0.04, "Mo": 0.01, "Br": 0.01, "je": 0.02, "ov": 0.11, "!\n": 0.02, "kn": 0.06, "Fa": 0.01, "vo": 0.06, "m,": 0.03, "w\n": 0.01, "lk": 0.03, "Si": 0.01, "Su": 0.01, "t'": 0.01, "eh": 0.02, "va": 0.04, "Wi": 0.01, "kl": 0.02, "wl": 0.03, "To": 0.01, "lw": 0.01, "e:": 0.01, "nf": 0.03, "ja": 0.01, "py": 0.01, "yb": 0.01, "o,": 0.01, "ek": 0.01, "p.": 0.01, "n,": 0.07, "Sa": 0.01, "eo": 0.02, "Fl": 0.01, "f\n": 0.07, "l,": 0.03, "dl": 0.05, "ci": 0.07, "gu": 0.05, "n?": 0.01, "? ": 0.05, "x ": 0.01, "; ": 0.04, "rc": 0.05, "Wa": 0.01, "r?": 0.01, "s?": 0.01, "dn": 0.01, "hy": 0.04, "?\n": 0.03, "yl": 0.01, "f,": 0.01, "Cl": 0.01, "Ir": 0.01, "g:": 0.01, "e?": 0.01, "No": 0.02, " G": 0.06, "Go": 0.05, "d'": 0.01, "Di": 0.01, "\" ": 0.02, "yi": 0.03, "cs": 0.01, "Mr": 0.02, "Ev": 0.01, "Te": 0.01, "s!": 0.01, "ya": 0.01, "ob": 0.03, "O ": 0.01, "Lo": 0.01, "hs": 0.01, "In": 0.02, "lp": 0.01, "k,": 0.02, "Vi": 0.01, "rv": 0.02, "e!": 0.01, "d;": 0.01, "d?": 0.01, "e;": 0.01, "r:": 0.01, "g,": 0.02, "t?": 0.01, "nr": 0.01, "h,": 0.02, "xi": 0.01, "p,": 0.01, "As": 0.01, "I ": 0.06, " \"": 0.02, "At": 0.01, "cc": 0.01, "ib": 0.03, "mn": 0.02, "w,": 0.01, "y'": 0.01, "oh": 0.01, "Ye": 0.01, "eb": 0.01, "Bl": 0.01, "Du": 0.01, "lm": 0.01, "iz": 0.01, "I'": 0.01, "'t": 0.01, "En": 0.01, "n:": 0.01, "df": 0.01, "c ": 0.02, "jo": 0.01, "nv": 0.01, "cy": 0.01, "wd": 0.01, "Fo": 0.01, "hm": 0.01, "rw": 0.01, "bs": 0.01, "iu": 0.01, "az": 0.01, "zi": 0.01, "s;": 0.01, "sf": 0.01, "yn": 0.01, "hl": 0.01, "bj": 0.01, "Cr": 0.02, "dm": 0.01, "Je": 0.01, "ym": 0.01, "bt": 0.01, "tf": 0.01, "-\n": 0.01, "Ly": 0.01, " -": 0.01}

// var trigrams = map[string]float64{"ced": 0.02, "ed ": 0.69, "d b": 0.14, " by": 0.09, "by ": 0.09, "oat": 0.02, "t. ": 0.06, " ve": 0.03, "ver": 0.17, "ers": 0.11, "sio": 0.03, "ion": 0.14, "on ": 0.24, "n b": 0.03, "ain": 0.15, "ine": 0.07, "nes": 0.06, "es.": 0.04, "s. ": 0.11, "rth": 0.03, "the": 1.74, "her": 0.31, "er ": 0.43, "r c": 0.03, " co": 0.24, "cor": 0.03, "orr": 0.02, "rec": 0.03, "ect": 0.06, "cti": 0.02, "tio": 0.09, "ons": 0.06, "no ": 0.03, "o d": 0.02, " de": 0.09, "de ": 0.07, "ort": 0.04, "tra": 0.06, "rai": 0.05, "ait": 0.02, "it ": 0.14, "t o": 0.16, " of": 0.76, "of ": 0.69, "f t": 0.27, " th": 1.85, "he ": 1.58, "rti": 0.02, "ist": 0.07, "st ": 0.16, "t a": 0.15, " as": 0.13, "as ": 0.35, "s a": 0.27, " a ": 0.35, "oun": 0.09, "ung": 0.03, "ng ": 0.54, " Ma": 0.02, "ame": 0.09, "mes": 0.02, "es ": 0.22, "hap": 0.04, "ter": 0.18, "t i": 0.1, "not": 0.12, " an": 0.84, "ani": 0.02, " di": 0.1, "itt": 0.05, "tti": 0.02, " in": 0.45, "in ": 0.42, "n a": 0.15, " ar": 0.06, "art": 0.08, "tes": 0.02, "d, ": 0.09, "mor": 0.06, "hos": 0.04, "ose": 0.06, "ses": 0.03, "es,": 0.04, "s, ": 0.12, "nce": 0.1, "ce ": 0.14, "e u": 0.03, " up": 0.08, "upo": 0.03, "pon": 0.03, "a t": 0.03, " ti": 0.06, "tim": 0.04, "ime": 0.04, "me ": 0.15, "e a": 0.28, "and": 0.89, "nd ": 0.87, "d a": 0.22, "ery": 0.05, "ry ": 0.1, " go": 0.05, "goo": 0.02, "ood": 0.07, "od ": 0.07, "d t": 0.38, "e i": 0.11, " it": 0.18, "t w": 0.14, " wa": 0.35, "was": 0.25, "s t": 0.19, "ere": 0.24, "re ": 0.29, "e w": 0.28, "a m": 0.03, " mo": 0.12, "ow ": 0.1, "com": 0.07, "min": 0.06, "ing": 0.62, "ng\n": 0.03, "dow": 0.05, "own": 0.07, "wn ": 0.06, " al": 0.12, "alo": 0.03, "lon": 0.07, "ong": 0.08, "g t": 0.11, "e r": 0.09, " ro": 0.06, "roa": 0.02, "ad ": 0.26, "thi": 0.11, "his": 0.45, "is ": 0.5, "s m": 0.06, "w t": 0.03, "tha": 0.22, "hat": 0.26, "at ": 0.37, "s c": 0.06, " do": 0.08, "ad\n": 0.02, "et ": 0.08, " ni": 0.03, "ice": 0.06, "cen": 0.03, "ens": 0.03, "ns ": 0.04, "s l": 0.05, " li": 0.2, "lit": 0.05, "ttl": 0.04, "tle": 0.06, "le ": 0.16, "e b": 0.15, " bo": 0.09, "boy": 0.02, " na": 0.03, "nam": 0.02, "med": 0.04, " ba": 0.07, "y t": 0.11, " tu": 0.04, "His": 0.04, "s f": 0.1, " fa": 0.14, "fat": 0.03, "ath": 0.09, "r t": 0.14, " to": 0.52, "tol": 0.02, "old": 0.08, "ld ": 0.18, "d h": 0.23, " hi": 0.58, "him": 0.2, "im ": 0.13, "m t": 0.08, "t s": 0.08, " st": 0.2, "sto": 0.05, "tor": 0.05, "ory": 0.02, "r l": 0.02, " lo": 0.11, "loo": 0.05, "ook": 0.06, "oke": 0.05, "ked": 0.06, " at": 0.11, "t h": 0.15, "thr": 0.06, "hro": 0.04, "rou": 0.09, "oug": 0.08, "ugh": 0.11, "gh ": 0.05, "h a": 0.06, " a\n": 0.04, "las": 0.04, "ass": 0.07, " he": 0.48, "e h": 0.25, " ha": 0.35, "had": 0.23, "air": 0.05, "y f": 0.03, "fac": 0.04, "ace": 0.08, "ce.": 0.03, "e.\n": 0.05, "He ": 0.14, "s b": 0.08, ". T": 0.14, " Th": 0.15, "The": 0.19, "e m": 0.1, " ca": 0.12, "cam": 0.03, "e d": 0.13, "n t": 0.34, "d w": 0.12, " wh": 0.25, "whe": 0.07, "ett": 0.02, "ty ": 0.05, "rne": 0.04, "ive": 0.06, "ved": 0.02, "ed:": 0.02, " sh": 0.11, "she": 0.06, "e s": 0.3, " so": 0.17, "d l": 0.05, " le": 0.06, "emo": 0.02, "mon": 0.03, "n p": 0.02, " pl": 0.05, "pla": 0.05, "lat": 0.03, "att": 0.02, "t.\n": 0.03, "   ": 0.07, ", t": 0.13, " wi": 0.21, "wil": 0.04, "ild": 0.02, "d r": 0.04, "ros": 0.03, "se ": 0.14, " bl": 0.04, "los": 0.03, "oss": 0.03, "som": 0.04, "e l": 0.1, "e g": 0.07, " gr": 0.09, "gre": 0.05, "ree": 0.05, "een": 0.06, "en ": 0.29, "lac": 0.03, " sa": 0.15, "ang": 0.06, "son": 0.03, "ng.": 0.03, "g. ": 0.02, "s h": 0.14, "s s": 0.12, "n w": 0.07, " wo": 0.14, "oth": 0.09, "eth": 0.02, "hen": 0.19, " yo": 0.11, "you": 0.12, "ou ": 0.08, " we": 0.15, "t t": 0.24, " be": 0.31, "bed": 0.02, "ed,": 0.03, ", f": 0.03, " fi": 0.1, "fir": 0.05, "irs": 0.03, "rst": 0.04, " is": 0.07, "s w": 0.12, "war": 0.05, "arm": 0.03, "rm ": 0.02, "n i": 0.07, "t g": 0.02, " ge": 0.02, "get": 0.02, "ets": 0.02, "ts ": 0.11, "col": 0.04, "d. ": 0.06, ". H": 0.12, " Hi": 0.03, "mot": 0.02, "er\n": 0.03, "ut ": 0.18, " on": 0.18, "e o": 0.23, "hee": 0.02, "eet": 0.03, " qu": 0.04, "que": 0.02, "r s": 0.05, " sm": 0.03, "ell": 0.13, "r h": 0.08, "ll ": 0.22, "l t": 0.06, "han": 0.08, "an ": 0.14, "n h": 0.13, "er.": 0.04, "r. ": 0.05, ". S": 0.03, "e p": 0.14, "lay": 0.03, "aye": 0.02, "d o": 0.14, " pi": 0.03, "ano": 0.02, "sai": 0.07, "ail": 0.02, "r's": 0.02, "'s ": 0.09, " ho": 0.09, "orn": 0.03, "e f": 0.19, " fo": 0.19, "for": 0.21, "or ": 0.24, "to ": 0.45, " da": 0.09, "anc": 0.04, "e. ": 0.1, " He": 0.11, "d:\n": 0.04, "a l": 0.03, " la": 0.09, " tr": 0.07, "cle": 0.03, "har": 0.03, "arl": 0.02, "rle": 0.02, "les": 0.09, "ant": 0.08, "nte": 0.07, "te ": 0.06, "e c": 0.18, " cl": 0.06, "cla": 0.02, "app": 0.03, "ppe": 0.03, "ped": 0.02, "ed.": 0.04, "hey": 0.09, "ey ": 0.1, "y w": 0.07, "wer": 0.12, " ol": 0.02, "lde": 0.02, "der": 0.09, "r a": 0.14, "nd\n": 0.07, "r b": 0.04, " bu": 0.07, "but": 0.05, "t u": 0.02, " un": 0.07, "s o": 0.21, " tw": 0.02, "two": 0.02, "o b": 0.04, " br": 0.08, "hes": 0.03, "s i": 0.1, "r p": 0.02, " pr": 0.12, "pre": 0.06, "res": 0.09, "ess": 0.15, "ss.": 0.02, "sh ": 0.03, "h w": 0.02, "wit": 0.16, "ith": 0.17, "th ": 0.18, "h t": 0.07, " ma": 0.13, "mar": 0.02, "roo": 0.02, "vel": 0.02, "lve": 0.02, "bac": 0.03, "ack": 0.05, "ck ": 0.05, "ich": 0.08, "cha": 0.05, "el ": 0.03, "avi": 0.02, "t b": 0.07, "nel": 0.02, "l. ": 0.02, " ga": 0.04, "ave": 0.08, "ve ": 0.09, "m a": 0.06, "a c": 0.03, "ach": 0.02, "cho": 0.02, "hou": 0.08, " ev": 0.06, "eve": 0.11, "bro": 0.04, "ght": 0.15, "ht ": 0.09, "ece": 0.02, "ue ": 0.02, " pa": 0.11, "ape": 0.03, "per": 0.05, "r.\n": 0.03, "ces": 0.03, "d i": 0.11, "umb": 0.02, "mbe": 0.02, "ber": 0.03, " se": 0.13, "ven": 0.07, "en.": 0.02, "n. ": 0.05, "y h": 0.05, "a d": 0.02, "ffe": 0.03, "fer": 0.03, "ren": 0.03, "ent": 0.22, "nt ": 0.16, "t f": 0.05, "ile": 0.07, "lee": 0.02, "en'": 0.02, "n's": 0.03, "d m": 0.05, ". W": 0.03, " Wh": 0.03, "gro": 0.02, "row": 0.03, "s g": 0.02, "oin": 0.03, "o m": 0.03, "arr": 0.02, "id ": 0.08, "d u": 0.04, "und": 0.09, "nde": 0.08, "e t": 0.3, " ta": 0.05, "tab": 0.02, "abl": 0.03, "ble": 0.07, "le.": 0.02, "aid": 0.07, "id:": 0.02, "ull": 0.02, "l o": 0.04, " ou": 0.08, "out": 0.13, "s e": 0.05, " ey": 0.05, "eye": 0.05, "yes": 0.04, "ise": 0.04, "s.\n": 0.05, "ide": 0.06, "nds": 0.04, "ds ": 0.08, " sw": 0.03, "g w": 0.02, ". A": 0.07, "l w": 0.03, "sho": 0.04, "tin": 0.08, "g a": 0.09, "he\n": 0.15, "ref": 0.03, "efe": 0.02, "fec": 0.02, "s u": 0.02, "ged": 0.02, "hem": 0.07, "em ": 0.04, "m o": 0.03, "h s": 0.02, "str": 0.07, "tro": 0.02, "ron": 0.02, "g c": 0.02, " cr": 0.05, "cri": 0.02, "rie": 0.08, "ies": 0.06, "e e": 0.07, "eni": 0.03, "nin": 0.07, " ai": 0.02, "ir ": 0.09, "r w": 0.05, "s p": 0.05, "chi": 0.03, "hil": 0.04, "ill": 0.1, "lly": 0.03, "ly ": 0.22, "y a": 0.12, " af": 0.03, "aft": 0.03, "fte": 0.04, "r e": 0.02, "y c": 0.03, " ch": 0.08, "ge ": 0.06, "all": 0.18, "lle": 0.06, "rs ": 0.09, "rea": 0.1, "eas": 0.05, "lea": 0.05, "eat": 0.09, "r o": 0.07, " or": 0.08, " fl": 0.06, "fle": 0.02, "ew ": 0.04, "lik": 0.06, "ike": 0.06, "ke ": 0.09, "hea": 0.12, "eav": 0.03, "y b": 0.03, " bi": 0.02, "rd ": 0.06, "y l": 0.03, "lig": 0.05, "igh": 0.12, "e k": 0.02, "on\n": 0.02, " fr": 0.15, "fri": 0.02, "rin": 0.08, "nge": 0.07, "f h": 0.1, "lin": 0.09, "e, ": 0.11, ", o": 0.02, "f s": 0.05, " si": 0.13, "t, ": 0.07, " re": 0.15, "eac": 0.02, " ru": 0.02, "ude": 0.03, " fe": 0.11, "fee": 0.02, "o r": 0.02, " no": 0.17, "now": 0.04, "w a": 0.02, "fel": 0.07, "elt": 0.04, "lt ": 0.04, "bod": 0.02, "ody": 0.02, "dy ": 0.03, "y s": 0.05, "ll\n": 0.02, "wea": 0.02, "eak": 0.03, "k a": 0.03, " am": 0.02, "ami": 0.02, "mid": 0.02, "g o": 0.05, "wat": 0.03, "ate": 0.09, "y. ": 0.05, "ick": 0.05, "m w": 0.02, "s n": 0.04, "ot ": 0.11, "t l": 0.03, "wou": 0.07, "oul": 0.17, "uld": 0.12, "be ": 0.07, "tai": 0.03, "n o": 0.08, "ne ": 0.1, "llo": 0.05, "low": 0.1, "ows": 0.02, "ws ": 0.02, "d.\n": 0.03, "ast": 0.07, "che": 0.06, "a s": 0.06, "sti": 0.07, "ink": 0.03, "m h": 0.03, "d g": 0.03, "ves": 0.03, "r i": 0.04, "cto": 0.02, "g h": 0.05, "cal": 0.05, "led": 0.08, "rid": 0.02, "day": 0.04, "ay ": 0.09, "y p": 0.02, " pu": 0.03, "udd": 0.02, "din": 0.05, "lan": 0.05, "ket": 0.02, "And": 0.03, "one": 0.09, "ask": 0.02, "Ste": 0.07, "tep": 0.08, "eph": 0.07, "phe": 0.07, "ans": 0.03, "swe": 0.02, "red": 0.11, " St": 0.05, " De": 0.02, "eda": 0.02, "dal": 0.02, "alu": 0.02, "lus": 0.03, "d s": 0.17, "d n": 0.07, "bee": 0.03, " ab": 0.05, "o a": 0.04, "cre": 0.03, "rep": 0.03, "abo": 0.04, "bou": 0.04, "fro": 0.12, "rom": 0.12, "om ": 0.13, " po": 0.06, "int": 0.11, "o p": 0.02, ", m": 0.02, "mak": 0.02, "aki": 0.02, "kin": 0.07, ". B": 0.03, " Bu": 0.03, "But": 0.04, "ish": 0.06, "sid": 0.04, "ock": 0.03, "cke": 0.03, "bel": 0.02, "ted": 0.1, " su": 0.07, "a b": 0.03, " An": 0.03, "als": 0.02, "so ": 0.03, "o t": 0.12, "o g": 0.02, " gi": 0.02, "giv": 0.02, "a f": 0.03, ". O": 0.02, "l h": 0.03, "e y": 0.02, "our": 0.1, "urs": 0.02, "rse": 0.03, "sel": 0.07, "elf": 0.05, " ex": 0.03, "ssi": 0.03, "on.": 0.02, "o s": 0.05, " sp": 0.07, "spe": 0.04, "pea": 0.04, "ys ": 0.03, "oll": 0.04, "leg": 0.02, "t d": 0.03, "y i": 0.04, "hal": 0.03, "cas": 0.02, "stl": 0.02, "n s": 0.06, "d p": 0.05, "up ": 0.04, "o h": 0.08, " ki": 0.02, "ss ": 0.1, ": a": 0.02, "d e": 0.03, "ret": 0.03, "ete": 0.02, "ten": 0.07, "end": 0.07, "ded": 0.04, "see": 0.05, "ee ": 0.03, "o c": 0.02, "ied": 0.04, "en\n": 0.02, "o f": 0.02, "shi": 0.02, "lli": 0.03, "t m": 0.03, "m i": 0.02, " if": 0.02, "if ": 0.02, "any": 0.03, "hin": 0.1, "o w": 0.02, " wr": 0.02, "rit": 0.03, "ite": 0.05, "hom": 0.02, "ome": 0.1, "nd,": 0.04, ", w": 0.05, "wha": 0.03, "did": 0.03, " pe": 0.04, "ch ": 0.13, "h o": 0.03, "doo": 0.02, "oor": 0.03, "sha": 0.04, "ake": 0.04, "ken": 0.03, "h h": 0.06, "er,": 0.03, "r, ": 0.05, ", h": 0.06, "sou": 0.07, "tan": 0.06, "ane": 0.02, "tte": 0.05, "eri": 0.05, "g i": 0.04, "in\n": 0.03, "bre": 0.03, ", a": 0.1, "car": 0.03, "ar ": 0.06, "d d": 0.05, " dr": 0.05, "off": 0.02, "f w": 0.03, "d c": 0.07, "m f": 0.02, "vin": 0.04, "hei": 0.07, "eir": 0.07, "cau": 0.02, "aug": 0.02, "whi": 0.11, "f a": 0.07, " sc": 0.03, "mag": 0.03, "age": 0.05, "ear": 0.17, "ful": 0.04, "ul ": 0.06, "fla": 0.02, " mu": 0.04, "boo": 0.02, ", b": 0.03, "ben": 0.02, "o l": 0.03, "ok ": 0.03, "k t": 0.02, "tru": 0.02, "gs ": 0.02, "sta": 0.09, "pin": 0.02, "ton": 0.02, " ye": 0.02, "s d": 0.04, "dge": 0.02, "l a": 0.05, " ot": 0.02, "s r": 0.03, " ra": 0.04, "ran": 0.07, "way": 0.06, ". I": 0.07, " It": 0.04, "It ": 0.04, " us": 0.02, "use": 0.06, "ele": 0.02, "hol": 0.04, "ays": 0.03, "stu": 0.03, "tud": 0.03, "e n": 0.05, "pas": 0.04, "ste": 0.07, "ins": 0.07, "des": 0.03, "m s": 0.02, "bet": 0.02, "ond": 0.03, "d f": 0.1, "hic": 0.08, "win": 0.04, "ind": 0.09, "ndo": 0.02, "mil": 0.03, "owa": 0.02, "n f": 0.04, "flo": 0.02, "owe": 0.05, "n c": 0.02, "how": 0.02, "ark": 0.04, "die": 0.03, " sl": 0.04, "a p": 0.03, "ead": 0.07, "uni": 0.02, "nit": 0.02, "ity": 0.04, "to\n": 0.03, "est": 0.1, "sen": 0.04, "enc": 0.07, "pel": 0.02, "try": 0.02, "onl": 0.02, "nly": 0.05, "rn ": 0.02, "g f": 0.03, "y d": 0.03, "uri": 0.02, "im.": 0.02, "dis": 0.04, "sea": 0.02, "ase": 0.04, "nts": 0.04, "ima": 0.03, "g b": 0.02, "bef": 0.04, "efo": 0.04, "ore": 0.08, "ire": 0.04, "re,": 0.02, ", l": 0.02, "ean": 0.02, "is\n": 0.04, "nk ": 0.03, "k o": 0.03, "tho": 0.07, "lim": 0.02, "my ": 0.03, " ne": 0.05, "in.": 0.02, " me": 0.07, "lls": 0.02, "ls ": 0.04, "nto": 0.05, "qua": 0.02, "are": 0.07, "tch": 0.02, "bec": 0.03, "eca": 0.03, "aus": 0.03, "ned": 0.09, "con": 0.06, "f f": 0.02, " A ": 0.03, "w h": 0.02, "rat": 0.02, "m. ": 0.02, "sit": 0.02, "iti": 0.03, "rig": 0.02, "bri": 0.02, " te": 0.05, "r f": 0.04, "uch": 0.03, "lov": 0.02, "ove": 0.11, "ely": 0.03, " kn": 0.05, "kne": 0.04, "new": 0.03, "ngs": 0.03, "nne": 0.02, "ges": 0.02, " ri": 0.03, "mer": 0.02, "ric": 0.02, "ica": 0.02, "mou": 0.02, "unt": 0.03, "nal": 0.02, "pri": 0.04, "es\n": 0.02, "man": 0.07, "a w": 0.02, "mad": 0.03, "ade": 0.04, "t n": 0.02, "ois": 0.02, "r d": 0.02, "inn": 0.02, "ner": 0.03, "r m": 0.02, "urn": 0.05, "n.\n": 0.02, " vo": 0.04, "voi": 0.04, "oic": 0.04, "clo": 0.04, "sed": 0.09, "hed": 0.05, "y, ": 0.05, "wen": 0.02, "hel": 0.03, "eld": 0.02, "l b": 0.02, "its": 0.05, "wal": 0.03, "alk": 0.03, "t e": 0.02, "ct ": 0.02, "as\n": 0.03, "tur": 0.08, "wor": 0.07, "ord": 0.05, "fal": 0.02, "sle": 0.02, "let": 0.02, "ly.": 0.02, "y.\n": 0.02, "y o": 0.08, "ote": 0.02, "tel": 0.03, "ole": 0.02, "sin": 0.09, "slo": 0.02, "owl": 0.02, "lou": 0.03, "oud": 0.02, "rem": 0.04, "eme": 0.06, "mem": 0.03, "emb": 0.03, "hit": 0.02, "y m": 0.02, "eel": 0.02, "t c": 0.03, "cou": 0.06, "rri": 0.03, "too": 0.05, "rni": 0.03, "tal": 0.03, "oom": 0.02, "ur ": 0.06, "rot": 0.02, "ard": 0.1, "tri": 0.03, "onf": 0.02, "sil": 0.04, "beg": 0.03, "ega": 0.02, "gan": 0.02, "ms ": 0.02, "rk ": 0.03, " mi": 0.07, "ed\n": 0.04, "lau": 0.02, "rac": 0.02, "fin": 0.03, "ger": 0.04, "n l": 0.02, " ov": 0.03, " ow": 0.02, "who": 0.05, "t p": 0.03, "n e": 0.03, "men": 0.08, "wee": 0.02, "s v": 0.02, " ea": 0.04, "ern": 0.02, "sse": 0.05, " aw": 0.03, "awa": 0.03, "qui": 0.04, "mus": 0.02, "ust": 0.04, "bea": 0.03, "eau": 0.02, "aut": 0.02, "rds": 0.05, "sec": 0.02, "ps ": 0.03, "hav": 0.03, "a g": 0.02, "n r": 0.02, "orl": 0.02, "rld": 0.02, "d y": 0.02, "tow": 0.03, "imp": 0.02, "dra": 0.02, "on,": 0.02, "n, ": 0.07, "rt ": 0.03, " ap": 0.02, "pro": 0.04, ", p": 0.02, "ure": 0.07, " cu": 0.02, "o o": 0.02, "n d": 0.02, "at\n": 0.03, "ple": 0.04, "eem": 0.02, "l f": 0.02, "pra": 0.03, "ray": 0.03, "g s": 0.03, "re.": 0.02, " op": 0.02, "ope": 0.03, "pen": 0.04, "ene": 0.05, "ars": 0.03, "rs.": 0.02, "nig": 0.02, "f l": 0.02, "en,": 0.03, "l, ": 0.03, "ari": 0.03, " ag": 0.06, "aga": 0.05, "gai": 0.05, ", s": 0.07, "dle": 0.02, "pan": 0.02, "ho ": 0.03, "wed": 0.02, " ci": 0.02, "ese": 0.03, "of\n": 0.06, "ngl": 0.02, "gle": 0.02, "ndi": 0.03, "nst": 0.05, "kno": 0.02, "mom": 0.02, "til": 0.04, "gra": 0.04, "ram": 0.02, "dar": 0.04, "; a": 0.02, "say": 0.03, "ips": 0.02, "sof": 0.02, "oft": 0.03, "ft ": 0.02, "ny ": 0.03, "hy ": 0.02, "ris": 0.04, "mas": 0.02, " va": 0.02, "cat": 0.02, "ati": 0.07, "l i": 0.02, "f c": 0.02, " du": 0.02, "th\n": 0.02, "ims": 0.03, "mse": 0.04, "ntr": 0.02, "nti": 0.02, "re\n": 0.02, "rel": 0.02, "us ": 0.06, " my": 0.03, "nat": 0.02, "n m": 0.02, "tat": 0.02, "e v": 0.03, "me.": 0.02, " No": 0.02, " Go": 0.05, "God": 0.05, "nch": 0.03, "ayi": 0.02, "yin": 0.03, "ngu": 0.02, "eal": 0.02, "al ": 0.06, "ily": 0.02, "h i": 0.02, "sci": 0.02, "tic": 0.03, "pai": 0.02, " en": 0.05, "m, ": 0.03, "eep": 0.02, " gl": 0.03, "glo": 0.02, "g u": 0.02, "esi": 0.02, "ous": 0.07, "spo": 0.02, "nse": 0.02, "has": 0.02, ", i": 0.03, "tre": 0.05, "ost": 0.03, "l s": 0.03, "isi": 0.02, "ein": 0.02, "ser": 0.03, "erv": 0.02, "mbl": 0.02, "dre": 0.03, "lf ": 0.04, "f i": 0.03, "orm": 0.02, " hu": 0.03, "bli": 0.02, "epe": 0.02, "ly,": 0.02, "mur": 0.02, "par": 0.03, ", c": 0.02, "saw": 0.02, "aw ": 0.02, "iet": 0.02, "tly": 0.05, "lam": 0.02, "rde": 0.02, "dea": 0.03, "len": 0.05, "f m": 0.02, "err": 0.02, "den": 0.06, " fu": 0.02, "g l": 0.02, "ng,": 0.02, "g, ": 0.02, "lic": 0.02, "bra": 0.02, "eli": 0.03, "gin": 0.03, "cro": 0.02, "h, ": 0.02, "hoo": 0.02, "can": 0.03, "ce,": 0.02, "ini": 0.02, "nis": 0.02, "ary": 0.02, "dde": 0.03, " I ": 0.06, "alt": 0.02, "tar": 0.02, "rch": 0.02, "sur": 0.02, "spi": 0.02, " ac": 0.03, "era": 0.02, "ift": 0.02, "rro": 0.02, "lif": 0.04, "ntl": 0.02, "dly": 0.02, "Mr ": 0.02, "il ": 0.02, "ili": 0.02, "f d": 0.02, "nea": 0.02, "inc": 0.02, "fol": 0.02, "lis": 0.03, "ife": 0.04, "fe ": 0.02, "ali": 0.02, "gen": 0.02, "ivi": 0.02, "atu": 0.02, "emp": 0.02, "ic ": 0.02, "fai": 0.02, "hum": 0.02, "acr": 0.02, "act": 0.02, "ibl": 0.02, "ien": 0.03, "nt,": 0.02, " vi": 0.02, "fou": 0.02, "iou": 0.02, "mpl": 0.02, "vil": 0.02, "eed": 0.02, " im": 0.04, "omp": 0.02, "mpa": 0.02, "ert": 0.02, "ual": 0.02, "anl": 0.02, "evi": 0.02, "Cra": 0.02}

func maxRow(ciphertexts [][]byte) int {
	var maxLength int = 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > maxLength {
			maxLength = len(ciphertext)
		}
	}
	return maxLength
}

func minRow(ciphertexts [][]byte) int {
	var minLength int = math.MaxInt32
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) < minLength {
			minLength = len(ciphertext)
		}
	}
	return minLength
}

func sliceContains(slice []byte, entry byte) bool {
	for _, item := range slice {
		if int(item) == int(entry) {
			return true
		}
	}
	return false
}

func findSingles(ciphertexts [][]byte) map[int][]byte {
	columnRepetitions := make(map[int][]byte)
	maxLength := maxRow(ciphertexts)
	for i := 0; i < maxLength; i++ {
		var seenBytes []byte
		columnRepetitions[i] = make([]byte, 0)
		for _, ciphertext := range ciphertexts {
			if i < len(ciphertext) {
				if sliceContains(seenBytes, ciphertext[i]) == true {
					columnRepetitions[i] = append(columnRepetitions[i], ciphertext[i])
				} else {
					seenBytes = append(seenBytes, ciphertext[i])
				}
			}
		}
	}
	filteredData := make(map[int][]byte)
	for key, val := range columnRepetitions {
		if len(val) > 0 {
			filteredData[key] = val
		}
	}
	return filteredData
}

type columnsData struct {
	Column []byte
	Index  int
}

func transpose(columns []columnsData, blockLength int) [][]byte {
	rows := make([][]byte, len(columns[0].Column))
	for i := 0; i < len(rows); i++ {
		rows[i] = make([]byte, blockLength)
		for j := 0; j < blockLength; j++ {
			for _, col := range columns {
				index := col.Index
				column := col.Column
				if index == j {
					rows[i][j] = column[i]
				}
			}
		}
	}
	return rows
}

func breakfixedNonceCTR(ciphertexts [][]byte, blockSize int) [][]byte {
	singleRepetitions := findSingles(ciphertexts)

	//topChars = [FREQUENCY, ASCIINUM] ASCIINUM is byte/int
	var topChars [][]float64 = sortByFrequencies(unigrams)
	var columnsStore []columnsData
	for key, bytes := range singleRepetitions {
		var keystreamCandidates []byte
		for _, candidate := range bytes {
			for i := 0; i < 60; i++ {
				keystreamByte := byte(int(topChars[i][1])) ^ candidate
				if sliceContains(keystreamCandidates, keystreamByte) == false {
					keystreamCandidates = append(keystreamCandidates, keystreamByte)
				}
			}
		}
		var bestTextScore float64 = math.MaxFloat64
		var bestColumn []byte
		numRows := float64(len(ciphertexts))
		for _, candidate := range keystreamCandidates {
			freqDist := make(map[byte]float64)
			var column []byte
			for _, row := range ciphertexts {
				if key >= len(row) {
					column = append(column, byte(32))
					continue
				}
				plainByte := row[key] ^ candidate
				column = append(column, plainByte)
				_, exists := freqDist[plainByte]
				if !exists {
					freqDist[plainByte] = float64(1) / numRows
				} else {
					freqDist[plainByte] = freqDist[plainByte] + float64(1)/numRows
				}
			}
			score := scoreDecipheredText(freqDist, unigrams)
			if score < bestTextScore {
				bestTextScore = score
				bestColumn = column
			}
		}
		columnsStore = append(columnsStore, columnsData{Column: bestColumn, Index: key})
	}
	// fmt.Println(columnsStore)
	return transpose(columnsStore, blockSize)
}

func textChunks(texts [][]byte, chunkLength int, maxLength int) [][][]byte {
	var textChunks [][][]byte
	for bs, be := 0, chunkLength; bs < maxLength; bs, be = bs+chunkLength, be+chunkLength {
		// chunk := make([][]byte, chunkLength)
		var chunk [][]byte
		for _, t := range texts {
			if be < len(t) {
				chunk = append(chunk, t[bs:be])
			} else {
				if bs < len(t) {
					chunk = append(chunk, t[bs:len(t)])
				} else {
					var x []byte
					chunk = append(chunk, x)
				}
			}
		}
		textChunks = append(textChunks, chunk)
	}
	// fmt.Println(textChunks)
	return textChunks
}

//challenge 3, 4 main
func fixedNonceCTR(filepath string) {
	f, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	var line string
	var ciphertexts [][]byte
	reader := bufio.NewReader(f)
	nonce := make([]byte, 8)
	key := randBytes(16)
	for {
		line, err = reader.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			break
		}
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			panic(err)
		}
		ciphertext := cryptAes128CTR(data, key, nonce)
		// plaintext := cryptAes128CTR(ciphertext, key, nonce)
		ciphertexts = append(ciphertexts, ciphertext)
	}
	// fmt.Println()
	//block length
	minRowLength := minRow(ciphertexts)
	maxRowLength := maxRow(ciphertexts)

	cipherChunks := textChunks(ciphertexts, minRowLength, maxRowLength)
	var plaintextsMeta [][][]byte

	for _, chunk := range cipherChunks {
		plaintextChunk := breakfixedNonceCTR(chunk, minRowLength)
		plaintextsMeta = append(plaintextsMeta, plaintextChunk)
	}
	// fmt.Println(len(plaintextsMeta))
	for i := 0; i < len(plaintextsMeta[0]); i++ {
		var toPrint string
		for _, plaintexts := range plaintextsMeta {
			toPrint = toPrint + string(plaintexts[i])
			// fmt.Println(string(plaintexts[i]))
		}
		fmt.Println(toPrint)
	}
}
