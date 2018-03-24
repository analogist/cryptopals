// Used in github.com/analogist/cryptopals for the Matasano cryptopals
// challenges. This constitutes a set of cryptanalysis tools written
// from scratch as an exercise.
package cryptanalysis

import (
	"errors"
	"sort"
	"io/ioutil"
	"bytes"
	"encoding/base64"
	"crypto/aes"
	crand "crypto/rand"
	mrand "math/rand"
	"time"
	// "fmt"
)

// Basic reimplementation of encoding/hex.Decode()
// Converts hex encoded string to raw byte array.
func DecodeHex(inputstr string) (output []byte, err error) {
	input := []byte(inputstr)
	if len(input) % 2 != 0 {
		return nil, errors.New("Hex string does not have an even length")
	}

	output = make([]byte, len(input)/2)
	for i := 0; i < len(output); i++ {
		// assuming little endian
		highnibble, err := decode1Hex(input[i*2])
		if err != nil {
			return nil, err
		}
		lownibble, err := decode1Hex(input[i*2+1])
		if err != nil {
			return nil, err
		}
		output[i] = highnibble << 4 | lownibble
	}
	return
}

func decode1Hex(input byte) (byte, error) {
	switch {
	case input >= '0' && input <= '9':
		input = input - '0'
	case input >= 'A' && input <= 'F':
		input = input - 'A' + 10
	case input >= 'a' && input <= 'f':
		input = input - 'a' + 10
	default:
		return 0, errors.New("Invalid hex byte")
	}
	return input, nil
}

// Basic reimplementation of encoding/hex.EncodeToString().
// Converts raw byte array to hex encoded string.
func EncodeHex(input []byte) (output string) {
	hexbytes := make([]byte, len(input)*2)
	hexarray := []byte("0123456789abcdef")

	for i := 0; i < len(input); i++ {
		hexbytes[i*2+1] = hexarray[input[i] & '\x0f'] // lower bit only
		hexbytes[i*2] = hexarray[input[i] >> 4]
	}

	output = string(hexbytes)

	return
}

// Wrap base64.StdEncoding.EncodeToString to wrap the library
func EncodeBase64(input []byte) (output string) {
	output = base64.StdEncoding.EncodeToString(input)
	return
}

// XOR two equal length byte arrays buf1 ^ buf2.
func XORBytes(buf1 []byte, buf2 []byte) (buf3 []byte, err error) {
	if len(buf1) != len(buf2) {
		return nil, errors.New("Buffer lengths not identical")
	}

	buf3 = make([]byte, len(buf1))

	for i := 0; i < len(buf1); i++ {
		buf3[i] = buf1[i] ^ buf2[i]
	}

	return
}

// XOR byte array of arbitrary length with single byte.
func XOR1Key(input []byte, key byte) (output []byte) {
	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key
	}

	return
}

// Checks decoding attempts for likelihood of plaintext english.
// Rates a single byte array as a single score.
// Positive scores are more likely to be English,
// Negative scores are more likely to be encrypted bytes.
func ScoreEnglish(input []byte) (score int) {
	score = 0
	for i := 0; i < len(input); i++ {
		switch {
		case input[i] >= 'A' && input[i] <= 'Z':
			fallthrough
		case input[i] >= 'a' && input[i] <= 'z':
			fallthrough
		case input[i] == ' ':
			score += 2
		case input[i] >= '0' && input[i] <= '9':
			score += 2
		case input[i] >= '!' && input[i] <= '/':
			fallthrough
		case input[i] >= '[' && input[i] <= '`':
			score += 1
		default:
			score -= 2
		}

		for _, c := range "ETAOINetaoinSHRDLUshrdlu" {
			if input[i] == byte(c) {
				score += 2
			}
		}
	}
	return
}

// Brute forces Vigenère/shifted byte arrays, returns the byte
// that decoded to the highest likelihood of plaintext English.
func BruteForce1XOR(inputstring []byte) (byte) {
	type keysort struct {
		Key byte
		Score int
	}

	keyslice := make([]keysort, 256)
	for key := byte(0); key < 255; key++ {
		inputdecode := XOR1Key(inputstring, key)
		keyslice[key].Key = key
		keyslice[key].Score = ScoreEnglish(inputdecode)
	}

	sort.Slice(keyslice, func(i, j int) bool { return keyslice[i].Score < keyslice[j].Score })

	return keyslice[255].Key
}

// Implements Vigenère cipher, with iterated byte shifts represented by
// each byte in the byte array key.
func XORVigKey(input []byte, key []byte) (output []byte) {
	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		vignereidx := i % len(key)
		output[i] = input[i] ^ key[vignereidx]
	}

	return
}

// Computes Hamming distance of two byte arrays; outputs distance,
// which represents the minimum bit flips required to make byte arrays
// identical.
func HammingDist(buf1 []byte, buf2 []byte) (distance int, err error) {
	if len(buf1) != len(buf2) {
		return 0, errors.New("Buffer lengths not identical")
	}

	distance = 0

	for i := 0; i < len(buf1); i++ {
		bufxor := buf1[i] ^ buf2[i]
		for bufxor != 0 {
			distance++
			bufxor &= bufxor-1
		}
	}

	return
}

// Read in a Base64-encoded byte array and output a raw byte array.
func DecodeBase64(input []byte) (output []byte, err error) {
	bytestodecode := base64.StdEncoding.DecodedLen(len(input))
	output = make([]byte, bytestodecode)

	bytesdecoded, err := base64.StdEncoding.Decode(output, input)
	if err != nil {
		return nil, err
	}

	// truncate for any \n, \r, invalid chars in Base64 string
	output = output[:bytesdecoded]

	return output, nil
}

// Read in a Base64-encoded file and output a truncated byte array
// to the successfully decoded length.
func ReadBase64File(filename string) (datbytes []byte, err error) {
	datbase64, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	bytestodecode := base64.StdEncoding.DecodedLen(len(datbase64))
	datbytes = make([]byte, bytestodecode)
	bytesdecoded, _ := base64.StdEncoding.Decode(datbytes, datbase64)
	datbytes = datbytes[:bytesdecoded]

	return
}

type blocksizestruct struct {
	Size int
	Score float32
}

// Read in input bytes and determine most likely shift block size by
// Hamming distance.
func DecodeBlocksize(input []byte, MaxBlockSizeTry int) (blocksizearr []blocksizestruct, err error) {
	// var blocksizearr []blocksizestruct
	for blocksize := 2; blocksize < MaxBlockSizeTry; blocksize++ {

		var blocksizetest blocksizestruct // Holds each stored decode attempt
		blockstotest := len(input) / blocksize
		if blockstotest < 2 {
			return []blocksizestruct{}, errors.New("Not enough bytes in input to test blocksize")
		}

		hamdistsum := 0
		blocktestcount := 0
		startblock := 0
		// Compare:
		// 0-1, 0-2, 0-3, 0-4, ... 0-(blockstotest-1)
		// 1-2, 1-3, 1-4, ... 1-(blockstotest-1)
		// 2-3, 2-4, 2-5, ... 2-(blockstotest-1)
		for startblock != blockstotest {
			block1 := input[startblock*blocksize:(startblock+1)*blocksize]
			for blocks := startblock+1; blocks < blockstotest; blocks++ {
				block2 := input[(blocks)*blocksize:((blocks+1)*blocksize)]
				hamdist, err := HammingDist(block1, block2)
				if err != nil {
					return []blocksizestruct{}, err
				}
				// sums hamming distance
				hamdistsum += hamdist
				blocktestcount++
			}
			startblock++
		}

		blocksizetest.Size = blocksize
		blocksizetest.Score = float32(hamdistsum)/float32(blocksize)/float32(blocktestcount)
		// hamming distance sum needs to be normalized for blocksize and # of permutation tests

		blocksizearr = append(blocksizearr, blocksizetest)
	}
	sort.Slice(blocksizearr, func(i, j int) bool { return blocksizearr[i].Score < blocksizearr[j].Score })
	return blocksizearr, nil
}

// Decode most likely Vigenère cipher key given fixed keysize
func BruteForceVig(input []byte, keysize int) (keyattempt []byte) {
	bytesdecoded := len(input)
	keyattempt = make([]byte, keysize)

	for j := 0; j < keysize; j++ {
		input_segment := make([]byte, bytesdecoded/keysize)
		for i := 0; i < bytesdecoded/keysize; i++ {
			input_segment[i] = input[i*keysize+j]
		}
		keyattempt[j] = BruteForce1XOR(input_segment)
	}

	return
}

// Decode ECB-mode AES, given ciphertext and key, with standard AES blocksize.
func AESDecodeECB(input []byte, key []byte) (output []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(input) % aes.BlockSize != 0 {
		return nil, errors.New("File cipher contents not a multiple of AES blocksize")
    }

    output = make([]byte, len(input))

    for i := 0; i < len(input) / aes.BlockSize; i++ {

		blockstart := i*aes.BlockSize
		blockstop := (i+1)*aes.BlockSize // not -1, because [:] exclusive

		block.Decrypt(output[blockstart:blockstop], input[blockstart:blockstop])
    }

    return output, nil
}

// Detect if ECB-mode AES was used by detecting each block's similarity to
// any other blocks in the input ciphertext. Outputs minimum hamming distance
// observed, ham_min.
// The closer ham_min is to 0, the more likely ECB-mode blocks are present.
func AESDetectECB(input []byte, blocksizeoverride ...int) (ham_min int, err error) {
	blocksize := aes.BlockSize // default is AES
	if len(blocksizeoverride) > 1 {
		return 999, errors.New("too many blocksizes specified")
	} else if len(blocksizeoverride) == 1 {
		blocksize = blocksizeoverride[0] // if you really wanted to override blocksize
	}
	MaxHamming := blocksize*8

	if len(input) % blocksize != 0 {
		return MaxHamming, errors.New("input byte len not multiple of block size")
	}

	blockstotest := len(input) / blocksize

	ham_min = MaxHamming // start the minimum distance at the max possible

	startblock := 0

	// Compare:
	// 0-1, 0-2, 0-3, 0-4, ... 0-(blockstotest-1)
	// 1-2, 1-3, 1-4, ... 1-(blockstotest-1)
	// 2-3, 2-4, 2-5, ... 2-(blockstotest-1)
	for startblock != blockstotest {
		block1 := input[startblock*blocksize:(startblock+1)*blocksize]
		for blocks := startblock+1; blocks < blockstotest; blocks++ {
			block2 := input[(blocks)*blocksize:((blocks+1)*blocksize)]
			hamdist, err := HammingDist(block1, block2)
			if err != nil {
				return ham_min, err
			}
			ham_min = min(ham_min, hamdist)
		}
		startblock++
	}

	return ham_min, nil
}

func min(a, b int) (int) {
	if a > b {
		return b
	}
	return a
}

// Pads a byte array to arbitrary desired block length with PKCS7 padding.
func PadPKCS7ToLen(msg []byte, length int) ([]byte) {
	if len(msg) % length == 0 {
		return msg
	} else {
		padlen := length - (len(msg) % length)
		padding := bytes.Repeat([]byte{'\x04'}, padlen)
		msg = append(msg, padding...)
		return msg
	}
}

// Repeats byte array "msg" [length] times
func RepeatBytes(msg []byte, length int) ([]byte) {
	return bytes.Repeat(msg, length)
}

// Decode CBC-mode AES, given cipher, iv, and key.
func AESDecodeCBC(input []byte, iv []byte, key []byte) (output []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(input) % aes.BlockSize != 0 {
		return nil, errors.New("File cipher contents not a multiple of AES blocksize")
    }
    if len(iv) != aes.BlockSize {
		return nil, errors.New("Length of iv is not AES blocksize")
    }

    output = make([]byte, len(input))

    for i := 0; i < len(input) / aes.BlockSize; i++ {

		blockstart := i*aes.BlockSize
		blockstop := (i+1)*aes.BlockSize // not -1, because [:] exclusive
		P_i := make([]byte, aes.BlockSize)
		P_x := P_i

		block.Decrypt(P_i, input[blockstart:blockstop])

		if i == 0 {
			P_x, err = XORBytes(P_i, iv)
		} else {
			prevstart := (i-1)*aes.BlockSize
			P_x, err = XORBytes(P_i, input[prevstart:blockstart])
		}

		if err != nil {
			panic(err)
		}

		copy(output[blockstart:blockstop], P_x)
    }

    return output, nil
}

// Encode ECB-mode AES, given ciphertext and key, with standard AES blocksize.
// NEVER ACTUALLY USE THIS IN ANY SECURE CONTEXT.
// Well, never use anything here in any secure context but ESPECIALLY THIS.
func AESEncodeECB(input []byte, key []byte) (output []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(input) % aes.BlockSize != 0 {
		return nil, errors.New("File cipher contents not a multiple of AES blocksize")
    }

    output = make([]byte, len(input))

    for i := 0; i < len(input) / aes.BlockSize; i++ {

		blockstart := i*aes.BlockSize
		blockstop := (i+1)*aes.BlockSize // not -1, because [:] exclusive

		block.Encrypt(output[blockstart:blockstop], input[blockstart:blockstop])
    }

    return output, nil
}

// Encode CBC-mode AES, given cipher, iv, and key.
func AESEncodeCBC(input []byte, iv []byte, key []byte) (output []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(input) % aes.BlockSize != 0 {
		return nil, errors.New("File cipher contents not a multiple of AES blocksize")
    }
    if len(iv) != aes.BlockSize {
		return nil, errors.New("Length of iv is not AES blocksize")
    }

    output = make([]byte, len(input))

    for i := 0; i < len(input) / aes.BlockSize; i++ {

		blockstart := i*aes.BlockSize
		blockstop := (i+1)*aes.BlockSize // not -1, because [:] exclusive
		E_i := make([]byte, aes.BlockSize)

		if i == 0 {
			E_i, err = XORBytes(input[blockstart:blockstop], iv)
		} else {
			prevstart := (i-1)*aes.BlockSize
			E_i, err = XORBytes(input[blockstart:blockstop], output[prevstart:blockstart])
		}

		if err != nil {
			panic(err)
		}

		block.Encrypt(output[blockstart:blockstop], E_i)
    }

    return output, nil
}

// Creates a puzzle ciphertext with a random encryption key, 50% chance of ECB or CBC-mode.
// Random key, random iv
func AESPuzzleECBCBC(input []byte) (output []byte, err error) {
	// Gen random unknown key, iv
	randkey := make([]byte, aes.BlockSize)
	iv := randkey
	crand.Read(randkey) // this is secure random
	crand.Read(iv)

	mrand.Seed(time.Now().UTC().UnixNano()) // this is NOT secure random

	prepad := bytes.Repeat([]byte{'\x04'}, mrand.Intn(6) + 5) // 5-10 bytes padding
	postpad := bytes.Repeat([]byte{'\x04'}, mrand.Intn(6) + 5)
	plaintext := append(prepad, input...)
	plaintext = append(plaintext, postpad...)

	plaintext = PadPKCS7ToLen(plaintext, aes.BlockSize)

	if mrand.Intn(2) == 1 { // 1 == ECB
		output, err = AESEncodeECB(plaintext, randkey)
	} else { // 0 == CBC
		output, err = AESEncodeCBC(plaintext, iv, randkey)
	}

	if err != nil {
		return nil, err
	}

	return output, nil
}

// A known-plaintext AES byte-at-a-time puzzle with an unknown
// target string unknownbase64, encrypted with a fixed random key
func AESOracleECB(input []byte) (output []byte, err error) {
	const randkeybase64 = "5gp3ruRcNe5SRhGi6BxCzQ==" // fixed random
	const unknownbase64 = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK` // fixed text from s2c12

	randkey, err := DecodeBase64([]byte(randkeybase64))
	if err != nil {
		return nil, err
	}

	unknowntext, err := DecodeBase64([]byte(unknownbase64))
	if err != nil {
		return nil, err
	}

	input = append(input, unknowntext...)
	input = PadPKCS7ToLen(input, aes.BlockSize)
	output, err = AESEncodeECB(input, randkey)

	return
}

// Oracle function type: can be passed into Oracle detection or
// brute force functions with oracle type
type oracle func([]byte) ([]byte, error)

// Given an ECB oracle with form input || unknowntext, detect its
// blocksize
func DetectAESOracleBlocksize(oraclefunc oracle, MaxBlockSizeTry int) (blocksize int, err error) {
	blocksize = 0
	for i := 1; i <= MaxBlockSizeTry; i++ {
		myInput := RepeatBytes([]byte("A"), i*2)
		// 2*n byte injections are needed for blocksize n

		oracleOutput, err := oraclefunc(myInput)
		if err != nil {
			return blocksize, err
		}

		hammingScore, err := AESDetectECB(oracleOutput)
		if err != nil {
			return blocksize, err
		}
		if hammingScore == 0 {
			blocksize = i
			break
		}
	}
	if blocksize == 0 {
		return 0, errors.New("blocksize not found!")
	}

	return blocksize, nil
}

// Given an ECB oracle with form input || unknowntext,
// brute force unknowntext
func BruteForceAESOracleECB(oraclefunc oracle, blocksize int) (plaintext []byte, err error) {
	// Determine the length of the unknowntext
	oracleOutput, err := oraclefunc(nil)
	if err != nil {
		return nil, err
	}
	unknownlen := len(oracleOutput)
	plaintext = make([]byte, unknownlen)
	// Determine the # of blocks in unknowntext
	numblocks := unknownlen / blocksize

	// Brute force plaintext
	lastblock := RepeatBytes([]byte("A"), blocksize) // "-1th" block
	for block := 0; block < numblocks; block++ {
		blockstart := block*blocksize
		blockstop := (block+1)*blocksize
		blocktext := make([]byte, blocksize)

		knownpos := 0
		for ; knownpos < blocksize; knownpos++ {
			knownbyte := byte(255)
			myInput := make([]byte, blocksize-knownpos-1)
			// This part always feeds in blocksize-knownpos-1
			// bytes to create the byte-at-a-time oracle
			// at block boundary
			copy(myInput, lastblock[knownpos+1:blocksize])
			// No lastblock solved yet, use
			// AAAAAAAAAAAAAAA
			// AAAAAAAAAAAAAA
			// AAAAAAAAAAAAA
			// ...
			// Else use last block solved
			// BCDEFGHIJKLMNOP
			// CDEFGHIJKLMNOP
			// DEFGHIJKLMNOP
			// ...
			refOut, err := oraclefunc(myInput)
			if err != nil {
				return nil, err
			}
			for byteA := byte(0); byteA < 255; byteA++ {
				// This part always feeds in blocksize bytes
				// tryInput = [myInput][blocktext]byteA
				// If block 0,
				// first [AAAAAAAAAAAAAAA][]A
				// then, [AAAAAAAAAAAAAA][A]B
				// then, [AAAAAAAAAAAAA][AB]C
				// If block >=1,
				// first [BCDEFGHIJKLMNOP][]A
				// then, [CDEFGHIJKLMNOP][A]B
				// then, [DEFGHIJKLMNOP][AB]C
				//
				// fmt.Printf("[%s][%s]%2x\n",
				// 	bytes.Replace(myInput, []byte{'\x0a'}, []byte{' '}, -1),
				// 	bytes.Replace(blocktext[:knownpos], []byte{'\x0a'}, []byte{' '}, -1),
				// 	byteA)
				tryInput := append(myInput, blocktext[:knownpos]...)
				tryInput = append(tryInput, byteA)
				tryOut, err := oraclefunc(tryInput)
				if err != nil {
					return nil, err
				}
				// tryOut[:blocksize] is always located at the 0th block, but copied from
				// either generated AAAAA... or last solved block
				// refOut[blockstart:blockstop] located at the actual block boundary tested
				if bytes.Compare(tryOut[:blocksize], refOut[blockstart:blockstop]) == 0 {
					knownbyte = byteA
					break
				}
			}
			if knownbyte == byte(255) {
				return nil, errors.New("failed at determining byte")
			}
			blocktext[knownpos] = knownbyte
		}
		copy(plaintext[blockstart:blockstop], blocktext)
		lastblock = blocktext
	}

	return plaintext, nil
}
