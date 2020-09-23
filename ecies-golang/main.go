package main

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	ecies "github.com/ecies/go"
	"hash"
	"io"
	"log"
	"os"
)

func main() {
	k, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	// ecies
	ciphertext, err := ecies.Encrypt(k.PublicKey, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	log.Printf("plaintext encrypted: %v\n", ciphertext)
	plaintext, err := ecies.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("ciphertext decrypted: %s\n", string(plaintext))

	// ecdsa
	var h hash.Hash
	h = md5.New()

	io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
	signhash := h.Sum(nil)
	privKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: k.Curve,
			X:     k.X,
			Y:     k.Y,
		},
		D:         k.D,
	}
	pubKey := ecdsa.PublicKey{
		Curve: k.Curve,
		X:     k.X,
		Y:     k.Y,
	}
	r, s, serr := ecdsa.Sign(rand.Reader, &privKey, signhash)
	if serr != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	result := ecdsa.Verify(&pubKey, signhash, r, s)
	if !result {
		log.Printf("verify failed.")
		os.Exit(-1)
	}
	log.Print("verify success")
}
