package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
)

// bock structur
type Block struct {
	Version       int32
	PrevBlockHash string
	MerkleRoot    string
	Timestamp     int64
	Bits          uint32
	Nonce         uint32
}

// calculate hash sha-256 of the block header
func calculateHash(block Block) [32]byte {
	header := strconv.Itoa(int(block.Version)) +
		block.PrevBlockHash +
		block.MerkleRoot +
		strconv.Itoa(int(block.Bits)) +
		strconv.Itoa(int(block.Nonce))

	return sha256.Sum256([]byte(header))
}
func main() {
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:8332",
		User:         "myrpcuser",
		Pass:         "mysecurepassword",
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatalf("Error creating new client: %v", err)
	}
	defer client.Shutdown()

	fmt.Println("Connectred to Bitcoin Core")

	blockTemplate, err := client.GetBlockTemplate(&btcjson.TemplateRequest{})
	if err != nil {
		log.Fatalf("Error getting block template: %v", err)
	}
	bits, err := strconv.ParseUint(blockTemplate.Bits, 16, 32)
	if err != nil {
		log.Fatalf("Error converting Bits to uint32: %v", err)
	}
	block := Block{
		Version:       blockTemplate.Version,
		PrevBlockHash: blockTemplate.PreviousHash,
		MerkleRoot:    blockTemplate.CoinbaseAux.Flags,
		Timestamp:     blockTemplate.CurTime,
		Bits:          uint32(bits),
	}
	target := big.NewInt(1)
	target.Lsh(target, uint(256-uint(bits)))

	var hashInt big.Int
	startTime := time.Now()

	fmt.Println("Mining...")

	for nonce := 0; nonce < int(^uint32(0)); nonce++ {
		block.Nonce = uint32(nonce)
		hash := calculateHash(block)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			endTime := time.Now()
			fmt.Printf("\nBlock mined!\n")
			fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))
			fmt.Printf("Nonce: %d\n", block.Nonce)
			fmt.Printf("Time taken: %s\n", endTime.Sub(startTime))
			break
		}
		if nonce%1000000 == 0 {
			fmt.Printf("\rCurrent nonce: %d", nonce)
		}
	}

}
