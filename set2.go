package main

import (
	"fmt"
	// "sort"
	// "bufio"
	// "io/ioutil"
	// "os"
    ca "github.com/analogist/cryptopals/cryptanalysis"
)

func main() {
	runset2()
}

func runset2() {
	fmt.Println("\n-------------------")
	fmt.Println("Set 2 / Challenge 9:")
	s2c9func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 2 / Challenge 10:")
	s2c10func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 2 / Challenge 11:")
	s2c11func()

	fmt.Println("\n-------------------")
	fmt.Println("Set 2 / Challenge 12:")
	s2c12func()

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 13:")
	// s2c13func()

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 14:")
	// s2c14func()

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 15:")
	// s2c15func()

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 16:")
	// s2c16func()
}

func s2c9func() {
	s2c9str := "YELLOW SUBMARINE"
	fmt.Printf("Padded: %2x", ca.PadPKCS7ToLen([]byte(s2c9str), 20))
}

func s2c10func() {
	s2c10bytes, err := ca.ReadBase64File("sets-txt/2/10.txt")
	if err != nil {
		panic(err)
	}

	iv := ca.RepeatBytes([]byte{'\x00'}, 16)
	s2c10text, err := ca.AESDecodeCBC(s2c10bytes, iv, []byte("YELLOW SUBMARINE"))

	fmt.Printf("%s", s2c10text)
}

func s2c11func() {
	s2c11text := []byte(
`THE WHEELS ON THE BUS GO ROUND AND ROUND
ROUND AND ROUND
ROUND AND ROUND
THE WHEELS ON THE BUS GO ROUND AND ROUND ALL THROUGH THE TOWN`)

	const s2c11rounds = 20
	fmt.Printf("Running %d rounds of ECB/CBC:\n", s2c11rounds)
	for i := 0; i < s2c11rounds; i++ {
		ciphertext, err := ca.AESPuzzleECBCBC(s2c11text)
		if err != nil {
			panic(err)
		}

		score, err := ca.AESDetectECB(ciphertext)
		if err != nil {
			panic(err)
		}

		var probablemode string
		if score <= 8 {
			probablemode = "ECB"
		} else {
			probablemode = "CBC"
		}

		fmt.Printf("Run %2d: %s (Hamming = %d)\n", i, probablemode, score)
	}
}

func s2c12func() {
	const MaxBlockSizeTry = 64

	blocksize, err := ca.DetectAESOracleBlocksize(ca.AESOracleECB, MaxBlockSizeTry)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Found ECB blocksize: %d\n", blocksize)

	plaintext, err := ca.BruteForceAESOracleECB(ca.AESOracleECB, blocksize)
        if err != nil {
            panic(err)
        }
	fmt.Printf("%s\n", plaintext)
}
