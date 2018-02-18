package main

import (
	"fmt"
	"errors"
	"sort"
	"bufio"
	"io/ioutil"
	"os"
	"crypto/aes"
	"encoding/base64"
)

func main() {
	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 1:")
	s1c1func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 2:")
	s1c2func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 3:")
	s1c3func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 4:")
	s1c4func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 5:")
	s1c5func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 6:")
	s1c6func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 7:")
	s1c7func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 1 / Challenge 8:")
	s1c8func()
}
func s1c1func() {

	s1c1hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Println("Hex:", s1c1hex)

	s1c1, err := decodehex(s1c1hex)
	fmt.Printf("%x\n",s1c1)
	if err != nil {
		panic(err)
	}

	s1c1b64 := base64.StdEncoding.EncodeToString(s1c1)
	fmt.Println("Base64:", s1c1b64)
}

func decodehex(inputstr string) (output []byte, err error) {
	input := []byte(inputstr)
	if len(input) % 2 != 0 {
		return nil, errors.New("Hex string does not have an even length")
	}

	output = make([]byte, len(input)/2)
	for i := 0; i < len(output); i++ {
		// assuming little endian
		highnibble, err := decode1hex(input[i*2])
		if err != nil {
			return nil, err
		}
		lownibble, err := decode1hex(input[i*2+1])
		if err != nil {
			return nil, err
		}
		output[i] = highnibble << 4 | lownibble
	}
	return
}

func decode1hex(input byte) (byte, error) {
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

func s1c2func() {

	s1c2hex1 := "1c0111001f010100061a024b53535009181c"
	s1c2hex2 := "686974207468652062756c6c277320657965"
	fmt.Println(s1c2hex1, "^", s1c2hex2)
	fmt.Println(" =")
	s1c2buf1, err := decodehex(s1c2hex1)
	if err != nil {
		panic(err)
	}
	s1c2buf2, err := decodehex(s1c2hex2)
	if err != nil {
		panic(err)
	}
	s1c2xor, err := xorbytes(s1c2buf1, s1c2buf2)
	if err != nil {
		panic(err)
	}
	fmt.Println(encodehex(s1c2xor))
}

func encodehex(input []byte) (output string) {
	hexbytes := make([]byte, len(input)*2)
	hexarray := []byte("0123456789abcdef")

	for i := 0; i < len(input); i++ {
		hexbytes[i*2+1] = hexarray[input[i] & '\x0f'] // lower bit only
		hexbytes[i*2] = hexarray[input[i] >> 4]
	}

	output = string(hexbytes)

	return
}

func xorbytes(buf1 []byte, buf2 []byte) (buf3 []byte, err error) {
	if len(buf1) != len(buf2) {
		return nil, errors.New("Buffer lengths not identical")
	}

	buf3 = make([]byte, len(buf1))

	for i := 0; i < len(buf1); i++ {
		buf3[i] = buf1[i] ^ buf2[i]
	}

	return
}

func s1c3func() {

	s1c3hex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	fmt.Printf("Ciphertext: \"%s\"\n", s1c3hex)
	s1c3, err := decodehex(s1c3hex)
	if err != nil {
		panic(err)
	}

	topkey := bruteforce1xor(s1c3)

	fmt.Printf("Top score: key 0x%2x decrypts to \"%s\"\n", topkey, xor1key(s1c3, topkey))

}

func xor1key(input []byte, key byte) (output []byte) {

	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key
	}

	return
}

func scoreenglish(input []byte) (score int) {
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

func bruteforce1xor(inputstring []byte) (byte) {

	type keysort struct {
		Key byte
		Score int
	}

	keyslice := make([]keysort, 256)
	for key := byte(0); key < 255; key++ {
		inputdecode := xor1key(inputstring, key)
		keyslice[key].Key = key
		keyslice[key].Score = scoreenglish(inputdecode)
	}

	sort.Slice(keyslice, func(i, j int) bool { return keyslice[i].Score < keyslice[j].Score })

	return keyslice[255].Key
}

func s1c4func() {

	type keysort struct {
		Line int
		Key byte
		Score int
		Plaintext []byte
	}

	s1c4file, err := os.Open("sets-txt/1/4.txt")
	if err != nil {
		panic(err)
	}
	defer s1c4file.Close()

	linescan := bufio.NewScanner(s1c4file)
	linecount := 0
	var keyslice []keysort

	for linescan.Scan() {

		var keyline keysort
		var key byte

		linecount++
		s1c4line, err := decodehex(linescan.Text())
		if err != nil {
			panic(err)
		}

		for key = 0; key < 255; key++ {
			s1c4decode := xor1key(s1c4line, byte(key))
			keyline.Line = linecount
			keyline.Key = key
			keyline.Score = scoreenglish(s1c4decode)
			keyline.Plaintext = s1c4decode

			keyslice = append(keyslice, keyline)
		}
	}

	keylen := len(keyslice)
	sort.Slice(keyslice, func(i, j int) bool { return keyslice[i].Score < keyslice[j].Score })
	fmt.Printf("Top score: line %d key 0x%2x decrypts to \"%s\"\n", keyslice[keylen-1].Line, keyslice[keylen-1].Key, keyslice[keylen-1].Plaintext)
}

func s1c5func() {

	s1c5txt := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	s1c5cipher := xorvigkey([]byte(s1c5txt), []byte("ICE"))

	fmt.Println("Plaintext:", s1c5txt)
	fmt.Println("Ciphertext:", encodehex(s1c5cipher))
}

func xorvigkey(input []byte, key []byte) (output []byte) {

	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		vignereidx := i % len(key)
		output[i] = input[i] ^ key[vignereidx]
	}

	return
}

func s1c6func() {
	s1c6teststr1 := "this is a test"
	s1c6teststr2 := "wokka wokka!!!"
	fmt.Println(s1c6teststr1, "<>", s1c6teststr2)
	dist, _ := hammingdist([]byte(s1c6teststr1), []byte(s1c6teststr2))
	fmt.Printf("Hamming distance: %d\n", dist)

	blockstotest := 30
	topblockscount := 5
	fmt.Printf("\nAnalyzing 6.txt with %d key block tests, top %d likely key sizes:\n", blockstotest, topblockscount)

	type keysizestruct struct {
		Size int
		Score float32
		DecodeScore int
		KeyAttempt []byte
	}
	var keysizetestarr []keysizestruct

	s1c6file, err := os.Open("sets-txt/1/6.txt")
	if err != nil {
		panic(err)
	}

	s1c6filestream := bufio.NewReader(s1c6file)

	for keysize := 2; keysize < 40; keysize++ {

		var keysizetest keysizestruct // Holds each stored decode attempt
		bytestoread := base64.StdEncoding.EncodedLen(blockstotest*keysize)
		bytestoread = bytestoread + bytestoread/60 // 1 every 60 chars will be garbage due to '\n'

		blockchunks64, err := s1c6filestream.Peek(bytestoread)
		if err != nil {
			panic(err)
		}

		blockchunks := make([]byte, blockstotest*keysize+2)
		bytesdecoded, _ := base64.StdEncoding.Decode(blockchunks, blockchunks64)
		if bytesdecoded < blockstotest*keysize {
			panic("Not enough bytes decoded from base64")
		}

		hamdistsum := 0
		for blocks := 0; blocks < blockstotest-1; blocks++ {
			block1 := blockchunks[blocks*keysize:(blocks+1)*keysize-1]
			block2 := blockchunks[(blocks+1)*keysize:((blocks+2)*keysize-1)]
			hamdist, err := hammingdist(block1, block2)
			if err != nil {
				panic(err)
			}
			hamdistsum += hamdist
		}

		keysizetest.Size = keysize
		keysizetest.Score = float32(hamdistsum)/float32(keysize)/float32(blockstotest-1)
		keysizetest.KeyAttempt = make([]byte, keysize)

		keysizetestarr = append(keysizetestarr, keysizetest)
	}

	sort.Slice(keysizetestarr, func(i, j int) bool { return keysizetestarr[i].Score < keysizetestarr[j].Score })

	s1c6file.Close()

	s1c6bytes, err := readbase64file("sets-txt/1/6.txt")
	if err != nil {
		panic(err)
	}
	bytesdecoded := len(s1c6bytes)

	for ki := 0; ki < topblockscount; ki++ {
		fmt.Printf("Key size %d hamming distance = %3.2f\n", keysizetestarr[ki].Size, keysizetestarr[ki].Score)

		keysize := keysizetestarr[ki].Size
		keyattempt := make([]byte, keysize)

		for j := 0; j < keysize; j++ {
			s1c6_segment := make([]byte, bytesdecoded/keysize)
			for i := 0; i < bytesdecoded/keysize; i++ {
				s1c6_segment[i] = s1c6bytes[i*keysize+j]
			}
			keyattempt[j] = bruteforce1xor(s1c6_segment)
		}
		keysizetestarr[ki].KeyAttempt = keyattempt
		keysizetestarr[ki].DecodeScore = scoreenglish(xorvigkey(s1c6bytes, keysizetestarr[ki].KeyAttempt))

		fmt.Printf("Most likely key: \"%s\" with score %d\n", keysizetestarr[ki].KeyAttempt, keysizetestarr[ki].DecodeScore)
	}

	sort.Slice(keysizetestarr, func(i, j int) bool { return keysizetestarr[i].DecodeScore > keysizetestarr[j].DecodeScore })
	fmt.Printf("\nUsing top-scoring key \"%s\" ", keysizetestarr[0].KeyAttempt)
	fmt.Printf("most likely decoded plaintext:\n%s", xorvigkey(s1c6bytes, keysizetestarr[0].KeyAttempt))

}

func hammingdist(buf1 []byte, buf2 []byte) (distance int, err error) {
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

func readbase64file(filename string) (datbytes []byte, err error) {
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

func s1c7func() {
	s1c7bytes, err := readbase64file("sets-txt/1/7.txt")
	if err != nil {
		panic(err)
	}

	key := []byte("YELLOW SUBMARINE")

    block, err := aes.NewCipher(key)
    if err != nil {
            panic(err.Error())
    }

    if len(s1c7bytes) % aes.BlockSize != 0 {
    	panic("File cipher contents not a multiple of AES blocksize")
    }

    s1c7plaintext := make([]byte, len(s1c7bytes))
    for i := 0; i < len(s1c7bytes) / aes.BlockSize; i++ {
    	blockstart := i*aes.BlockSize
    	blockstop := (i+1)*aes.BlockSize // not -1, because exclusive
    	block.Decrypt(s1c7plaintext[blockstart:blockstop],
    		s1c7bytes[blockstart:blockstop])
    }

    fmt.Printf("Decoding 7.txt using key \"YELLOW SUBMARINE\":\n")
	fmt.Printf("%s", s1c7plaintext)
}

func s1c8func() {
	type keysizestruct struct {
		Line int
		Hamdist int
		// DecodeScore int
		// KeyAttempt []byte
	}
	var keysizetestarr []keysizestruct

	s1c8file, err := os.Open("sets-txt/1/8.txt")
	if err != nil {
		panic(err)
	}
	defer s1c8file.Close()

	linescan := bufio.NewScanner(s1c8file)
	linecount := 0

	for linescan.Scan() {

		var linekey keysizestruct
		linecount++

		bytestodecode := base64.StdEncoding.DecodedLen(len(linescan.Bytes()))
		s1c8line := make([]byte, bytestodecode)
		bytesdecoded, err := base64.StdEncoding.Decode(s1c8line, linescan.Bytes())
		s1c8line = s1c8line[:bytesdecoded]
		if err != nil {
			panic(err)
		}

		if bytesdecoded%aes.BlockSize != 0 {
			panic("Error: bytes of line is not AES block size")
		}
		blockstotest := bytesdecoded / aes.BlockSize

		// hamdistsum := 0
		hammin := aes.BlockSize*8 // start the minimum comparison at the max possible

		startblock := 0
		stopblock := blockstotest-1

		for startblock != stopblock {
			for blocks := startblock+1; blocks < stopblock; blocks++ {
				block1 := s1c8line[startblock*aes.BlockSize:(startblock+1)*aes.BlockSize-1]
				block2 := s1c8line[(blocks+1)*aes.BlockSize:((blocks+2)*aes.BlockSize-1)]
				hamdist, err := hammingdist(block1, block2)
				if err != nil {
					panic(err)
				}
				hammin = min(hammin, hamdist)
			}
			startblock++
		}

		linekey.Line = linecount
		linekey.Hamdist = hammin

		keysizetestarr = append(keysizetestarr, linekey)
	}

	sort.Slice(keysizetestarr, func(i, j int) bool { return keysizetestarr[i].Hamdist < keysizetestarr[j].Hamdist })

	for ki := 0; ki < 5; ki++ {
		fmt.Printf("Line %d minimum inter-block hamming distance = %d\n", keysizetestarr[ki].Line, keysizetestarr[ki].Hamdist)
	}

}

func min(a, b int) (int) {
	if a > b {
		return b
	}
	return a
}
