package main

import (
	"fmt"
	"sort"
	"bufio"
	"os"
    ca "github.com/analogist/cryptopals/cryptanalysis"
)

func runset1() {
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

	s1c1, err := ca.DecodeHex(s1c1hex)
	fmt.Printf("%x\n",s1c1)
	if err != nil {
		panic(err)
	}

	s1c1b64 := base64.StdEncoding.EncodeToString(s1c1)
	fmt.Println("Base64:", s1c1b64)
}

func s1c2func() {

	s1c2hex1 := "1c0111001f010100061a024b53535009181c"
	s1c2hex2 := "686974207468652062756c6c277320657965"
	fmt.Println(s1c2hex1, "^", s1c2hex2)
	fmt.Println(" =")
	s1c2buf1, err := ca.DecodeHex(s1c2hex1)
	if err != nil {
		panic(err)
	}
	s1c2buf2, err := ca.DecodeHex(s1c2hex2)
	if err != nil {
		panic(err)
	}
	s1c2xor, err := ca.XORBytes(s1c2buf1, s1c2buf2)
	if err != nil {
		panic(err)
	}
	fmt.Println(ca.EncodeHex(s1c2xor))
}

func s1c3func() {

	s1c3hex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	fmt.Printf("Ciphertext: \"%s\"\n", s1c3hex)
	s1c3, err := ca.DecodeHex(s1c3hex)
	if err != nil {
		panic(err)
	}

	topkey := ca.BruteForce1XOR(s1c3)

	fmt.Printf("Top score: key 0x%2x decrypts to \"%s\"\n", topkey, ca.XOR1Key(s1c3, topkey))

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
		s1c4line, err := ca.DecodeHex(linescan.Text())
		if err != nil {
			panic(err)
		}

		for key = 0; key < 255; key++ {
			s1c4decode := ca.XOR1Key(s1c4line, byte(key))
			keyline.Line = linecount
			keyline.Key = key
			keyline.Score = ca.ScoreEnglish(s1c4decode)
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

	s1c5cipher := ca.XORVigKey([]byte(s1c5txt), []byte("ICE"))

	fmt.Println("Plaintext:", s1c5txt)
	fmt.Println("Ciphertext:", ca.EncodeHex(s1c5cipher))
}

func s1c6func() {
	s1c6teststr1 := "this is a test"
	s1c6teststr2 := "wokka wokka!!!"
	fmt.Println(s1c6teststr1, "<>", s1c6teststr2)
	dist, _ := ca.HammingDist([]byte(s1c6teststr1), []byte(s1c6teststr2))
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

		// This is slightly more than base64.StdEncoding.EncodedLen() due to '\n'
		bytestoread := (blockstotest*keysize + 2) * 8 / 6 // every 8 char is 6 bytes
		bytestoread = bytestoread + bytestoread/60 + 2 // 1 every 60 chars will be garbage due to '\n'

		blockchunks64, err := s1c6filestream.Peek(bytestoread)
		if err != nil {
			panic(err)
		}

		blockchunks, err := ca.DecodeBase64(blockchunks64)
		if err != nil {
			panic(err)
		}

		bytesdecoded := len(blockchunks)
		if bytesdecoded < blockstotest*keysize {
			panic("Not enough bytes decoded from base64")
		}

		hamdistsum := 0
		for blocks := 0; blocks < blockstotest-1; blocks++ {
			block1 := blockchunks[blocks*keysize:(blocks+1)*keysize-1]
			block2 := blockchunks[(blocks+1)*keysize:((blocks+2)*keysize-1)]
			hamdist, err := ca.HammingDist(block1, block2)
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

	s1c6bytes, err := ca.ReadBase64File("sets-txt/1/6.txt")
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
			keyattempt[j] = ca.BruteForce1XOR(s1c6_segment)
		}
		keysizetestarr[ki].KeyAttempt = keyattempt
		keysizetestarr[ki].DecodeScore = ca.ScoreEnglish(ca.XORVigKey(s1c6bytes, keysizetestarr[ki].KeyAttempt))

		fmt.Printf("Most likely key: \"%s\" with score %d\n", keysizetestarr[ki].KeyAttempt, keysizetestarr[ki].DecodeScore)
	}

	sort.Slice(keysizetestarr, func(i, j int) bool { return keysizetestarr[i].DecodeScore > keysizetestarr[j].DecodeScore })
	fmt.Printf("\nUsing top-scoring key \"%s\" ", keysizetestarr[0].KeyAttempt)
	fmt.Printf("most likely decoded plaintext:\n%s", ca.XORVigKey(s1c6bytes, keysizetestarr[0].KeyAttempt))

}

func s1c7func() {
	s1c7bytes, err := ca.ReadBase64File("sets-txt/1/7.txt")
	if err != nil {
		panic(err)
	}

	key := []byte("YELLOW SUBMARINE")

	s1c7plaintext, err := ca.AESDecodeECB(s1c7bytes, key)
	if err != nil {
		panic(err)
	}

    fmt.Printf("Decoding 7.txt using key \"YELLOW SUBMARINE\":\n")
	fmt.Printf("%s", s1c7plaintext)
}

func s1c8func() {
	type keysizestruct struct {
		Line int
		Hamdist int
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

		s1c8line, err := ca.DecodeBase64(linescan.Bytes())
		if err != nil {
			panic(err)
		}

		linekey.Line = linecount
		linekey.Hamdist, err = ca.DetectECB(s1c8line)
		if err != nil {
			panic(err)
		}

		keysizetestarr = append(keysizetestarr, linekey)
	}

	sort.Slice(keysizetestarr, func(i, j int) bool { return keysizetestarr[i].Hamdist < keysizetestarr[j].Hamdist })

	for ki := 0; ki < 5; ki++ {
		fmt.Printf("Line %d minimum inter-block hamming distance = %d\n", keysizetestarr[ki].Line, keysizetestarr[ki].Hamdist)
	}

}
