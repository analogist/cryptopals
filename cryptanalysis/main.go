package cryptanalysis

import (
	"errors"
	"sort"
	"io/ioutil"
	"bytes"
	"encoding/base64"
)

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

func XOR1Key(input []byte, key byte) (output []byte) {

	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key
	}

	return
}

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

func XORVigKey(input []byte, key []byte) (output []byte) {

	output = make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		vignereidx := i % len(key)
		output[i] = input[i] ^ key[vignereidx]
	}

	return
}

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


func Min(a, b int) (int) {
	if a > b {
		return b
	}
	return a
}

func PadPKCS7ToLen(msg []byte, length int) ([]byte) {

	if len(msg) % length == 0 {
		return msg
	} else {
		// completeblocks := int(len(msg) / length)
		padlen := length - (len(msg) % length)
		padding := bytes.Repeat([]byte{'\x04'}, padlen)
		msg = append(msg, padding...)
		return msg
	}
}
