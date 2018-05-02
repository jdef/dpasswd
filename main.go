package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/tredoe/osutil/user/crypt/common"
	crypt "github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

func main() {
	flag.CommandLine.Parse(os.Args[1:])
	args := flag.CommandLine.Args()

	if len(args) < 1 {
		panic("expected at least one argument")
	}

	key := ([]byte)(args[0])
	if len(key) == 1 && key[0] == '-' {
		// read password from stdin
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
		key = b
	}

	c := crypt.New()

	var salt []byte
	if len(args) > 1 {
		salt = ([]byte)(args[1])
	} else {
		s := crypt.GetSalt()
		salt = GenerateWRounds(s, s.SaltLenMax, 656000)
	}

	hash, err := c.Generate(key, salt)

	if err != nil {
		panic(err)
	}

	fmt.Println(hash)
}

func GenerateWRounds(s common.Salt, length, rounds int) []byte {
	if length > s.SaltLenMax {
		length = s.SaltLenMax
	} else if length < s.SaltLenMin {
		length = s.SaltLenMin
	}
	if rounds < 0 {
		rounds = s.RoundsDefault
	} else if rounds < s.RoundsMin {
		rounds = s.RoundsMin
	} else if rounds > s.RoundsMax {
		rounds = s.RoundsMax
	}

	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen += 1
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	roundsText := ""
	if rounds != s.RoundsDefault {
		roundsText = "rounds=" + strconv.Itoa(rounds)
	}

	out := make([]byte, len(s.MagicPrefix)+len(roundsText)+length+1)
	copy(out, s.MagicPrefix)
	copy(out[len(s.MagicPrefix):], []byte(roundsText))
	out[len(s.MagicPrefix)+len(roundsText)] = '$'
	copy(out[len(s.MagicPrefix)+len(roundsText)+1:], common.Base64_24Bit(salt))
	return out
}
