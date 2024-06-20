package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"gopkg.in/ini.v1"
)

// Define the Block structure
type Block struct {
	Version       int32
	PrevBlockHash string
	MerkleRoot    string
	Timestamp     int64
	Bits          uint32
	Nonce         uint32
}

// Calculate SHA-256 hash of the block header and return it as a hex string
func calculateHash(block Block) string {
	header := strconv.Itoa(int(block.Version)) +
		block.PrevBlockHash +
		block.MerkleRoot +
		strconv.FormatInt(block.Timestamp, 10) +
		strconv.Itoa(int(block.Bits)) +
		strconv.Itoa(int(block.Nonce))

	hash := sha256.Sum256([]byte(header))
	return hex.EncodeToString(hash[:])
}

// Calculate the Merkle Root for the transactions
func calculateMerkleRoot(txns []string) string {
	if len(txns) == 0 {
		return ""
	}

	if len(txns) == 1 {
		return txns[0]
	}

	var newLevel []string
	for i := 0; i < len(txns); i += 2 {
		if i+1 < len(txns) {
			hash := sha256.Sum256([]byte(txns[i] + txns[i+1]))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		} else {
			hash := sha256.Sum256([]byte(txns[i] + txns[i]))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		}
	}

	return calculateMerkleRoot(newLevel)
}

func mineBlock(block Block, target *big.Int, startNonce, endNonce uint32, result chan<- Block, stats chan<- int, wg *sync.WaitGroup, mutex *sync.Mutex) {
	defer wg.Done()
	var hashInt big.Int
	hashes := 0

	for nonce := startNonce; nonce <= endNonce; nonce++ {
		block.Nonce = nonce
		hash := calculateHash(block)
		hashInt.SetBytes([]byte(hash))
		hashes++

		if hashInt.Cmp(target) == -1 {
			mutex.Lock()
			result <- block
			mutex.Unlock()
			stats <- hashes
			return
		}
	}
	stats <- hashes
}

func loadConfig() (*rpcclient.ConnConfig, error) {
	cfg, err := ini.Load("config.ini")
	if err != nil {
		return nil, fmt.Errorf("Failed to read config file: %v", err)
	}

	return &rpcclient.ConnConfig{
		Host:         cfg.Section("").Key("host").String(),
		User:         cfg.Section("").Key("rpcuser").String(),
		Pass:         cfg.Section("").Key("rpcpassword").String(),
		HTTPPostMode: true,
		DisableTLS:   true,
	}, nil
}
func setupLogger() (*log.Logger, *os.File, error) {
	file, err := os.OpenFile("mining.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to open log file: %v", err)
	}
	logger := log.New(file, "", log.LstdFlags)
	return logger, file, nil
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	client, err := rpcclient.New(config, nil)
	if err != nil {
		log.Fatalf("Error creating new client: %v", err)
	}
	defer client.Shutdown()

	logger, logFile, err := setupLogger()
	if err != nil {
		log.Fatalf("Error setting up logger: %v", err)
	}
	defer logFile.Close()

	logger.Println("Connected to Bitcoin Core")

	// Get block template
	blockTemplate, err := client.GetBlockTemplate(&btcjson.TemplateRequest{})
	if err != nil {
		log.Fatalf("Error getting block template: %v", err)
	}

	// Convert Bits from string to uint32
	bits, err := strconv.ParseUint(blockTemplate.Bits, 16, 32)
	if err != nil {
		log.Fatalf("Error converting Bits to uint32: %v", err)
	}

	// Calculate the Merkle Root for the transactions
	var txns []string
	for _, tx := range blockTemplate.Transactions {
		txns = append(txns, tx.TxID)
	}
	merkleRoot := calculateMerkleRoot(txns)

	block := Block{
		Version:       blockTemplate.Version,
		PrevBlockHash: blockTemplate.PreviousHash,
		MerkleRoot:    merkleRoot,
		Timestamp:     blockTemplate.CurTime,
		Bits:          uint32(bits),
	}

	target := big.NewInt(1)
	target.Lsh(target, uint(256-uint(bits)))

	result := make(chan Block)
	stats := make(chan int)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	numGoroutines := 8
	nonceRange := uint32(^uint32(0)) / uint32(numGoroutines)

	startTime := time.Now()
	fmt.Println("Mining...")

	for i := 0; i < numGoroutines; i++ {
		startNonce := uint32(i) * nonceRange
		endNonce := startNonce + nonceRange - 1

		wg.Add(1)
		go mineBlock(block, target, startNonce, endNonce, result, stats, &wg, &mutex)
	}

	go func() {
		wg.Wait()
		close(result)
		close(stats)
	}()

	minedBlock := <-result
	endTime := time.Now()

	totalHashes := 0
	for hashCount := range stats {
		totalHashes += hashCount
	}

	fmt.Printf("\nBlock mined!\n")
	fmt.Printf("Hash: %s\n", calculateHash(minedBlock))
	fmt.Printf("Nonce: %d\n", minedBlock.Nonce)
	fmt.Printf("Time taken: %s\n", endTime.Sub(startTime))
	fmt.Printf("Total hashes: %d\n", totalHashes)
	fmt.Printf("Hashes per second: %f\n", float64(totalHashes)/endTime.Sub(startTime).Seconds())
}
