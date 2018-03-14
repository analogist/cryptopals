package main

import (
	"fmt"
	// "errors"
	// "sort"
	// "bufio"
	// "io/ioutil"
	// "os"
	// "crypto/aes"
	// "encoding/base64"
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

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 11:")
	// s2c11func()

	// fmt.Println("\n-------------------")
	// fmt.Println("Set 2 / Challenge 12:")
	// s2c12func()

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
	fmt.Printf("Padded: %2x", padpkcs7tolen([]byte(s2c9str), 20))
}

func s2c10func() {
	
}