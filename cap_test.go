package capserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	// Test with nil config
	cap := New(nil)
	if cap == nil {
		t.Fatal("Expected non-nil Cap instance")
	}
	if cap.config.TokensStorePath != DefaultTokensStore {
		t.Errorf("Expected default tokens store path %s, got %s", DefaultTokensStore, cap.config.TokensStorePath)
	}

	// Test with custom config
	customConfig := &CapConfig{
		TokensStorePath: "./test_tokens.json",
		NoFSState:       true,
	}
	cap2 := New(customConfig)
	if cap2.config.TokensStorePath != "./test_tokens.json" {
		t.Errorf("Expected custom tokens store path ./test_tokens.json, got %s", cap2.config.TokensStorePath)
	}
	if !cap2.config.NoFSState {
		t.Error("Expected NoFSState to be true")
	}
}

func TestCreateChallenge(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with default config
	challenge, err := cap.CreateChallenge(nil)
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}
	if len(challenge.Challenge) != DefaultChallengeCount {
		t.Errorf("Expected %d challenges, got %d", DefaultChallengeCount, len(challenge.Challenge))
	}
	if challenge.Token == "" {
		t.Error("Expected non-empty token")
	}
	if challenge.Expires <= time.Now().UnixMilli() {
		t.Error("Expected future expiration time")
	}

	// Test with custom config
	customConfig := &ChallengeConfig{
		ChallengeCount:      10,
		ChallengeSize:       16,
		ChallengeDifficulty: 2,
		ExpiresMs:           30000,
		Store:               true,
	}
	customChallenge, err := cap.CreateChallenge(customConfig)
	if err != nil {
		t.Fatalf("Failed to create custom challenge: %v", err)
	}
	if len(customChallenge.Challenge) != 10 {
		t.Errorf("Expected 10 challenges, got %d", len(customChallenge.Challenge))
	}

	// Verify challenge structure
	for i, ch := range customChallenge.Challenge {
		if len(ch[0]) != 16 {
			t.Errorf("Challenge %d: expected salt length 16, got %d", i, len(ch[0]))
		}
		if len(ch[1]) != 2 {
			t.Errorf("Challenge %d: expected target length 2, got %d", i, len(ch[1]))
		}
	}

	// Test with store=false
	noStoreConfig := &ChallengeConfig{Store: false}
	noStoreChallenge, err := cap.CreateChallenge(noStoreConfig)
	if err != nil {
		t.Fatalf("Failed to create no-store challenge: %v", err)
	}
	if noStoreChallenge.Token != "" {
		t.Error("Expected empty token for no-store challenge")
	}
}

func TestRedeemChallenge(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with invalid input
	result, err := cap.RedeemChallenge(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for nil solution")
	}
	if result.Message != "Invalid body" {
		t.Errorf("Expected 'Invalid body' message, got '%s'", result.Message)
	}

	// Test with non-existent token
	invalidSolution := &Solution{
		Token:     "nonexistent",
		Solutions: [][]interface{}{{"salt", "target", 123}},
	}
	result, err = cap.RedeemChallenge(invalidSolution)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for non-existent token")
	}
	if result.Message != "Challenge expired" {
		t.Errorf("Expected 'Challenge expired' message, got '%s'", result.Message)
	}

	// Create a valid challenge
	challenge, err := cap.CreateChallenge(&ChallengeConfig{
		ChallengeCount:      1,
		ChallengeDifficulty: 1, // Very easy for testing
		Store:               true,
	})
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}

	// Test with invalid solution
	invalidSol := &Solution{
		Token:     challenge.Token,
		Solutions: [][]interface{}{{challenge.Challenge[0][0], challenge.Challenge[0][1], 999999}},
	}
	result, err = cap.RedeemChallenge(invalidSol)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for invalid solution")
	}
	if result.Message != "Invalid solution" {
		t.Errorf("Expected 'Invalid solution' message, got '%s'", result.Message)
	}
}

func TestValidateToken(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with invalid token format
	result, err := cap.ValidateToken("invalid", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for invalid token format")
	}

	// Test with non-existent token
	result, err = cap.ValidateToken("id:token", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for non-existent token")
	}
}

func TestCleanExpiredTokens(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Add some expired tokens
	expiredTime := time.Now().UnixMilli() - 1000
	cap.config.State.TokensList["expired1"] = expiredTime
	cap.config.State.TokensList["expired2"] = expiredTime
	cap.config.State.TokensList["valid"] = time.Now().UnixMilli() + 60000

	// Add expired challenge
	cap.config.State.ChallengesList["expired_challenge"] = &ChallengeData{
		Expires: expiredTime,
		Token:   "expired_challenge",
	}

	changed := cap.cleanExpiredTokens()
	if !changed {
		t.Error("Expected tokens to be changed")
	}

	if len(cap.config.State.TokensList) != 1 {
		t.Errorf("Expected 1 token remaining, got %d", len(cap.config.State.TokensList))
	}
	if _, exists := cap.config.State.TokensList["valid"]; !exists {
		t.Error("Expected valid token to remain")
	}

	if len(cap.config.State.ChallengesList) != 0 {
		t.Errorf("Expected 0 challenges remaining, got %d", len(cap.config.State.ChallengesList))
	}
}

func TestGenerateRandomHex(t *testing.T) {
	// Test various lengths
	lengths := []int{1, 2, 8, 16, 32, 64}
	for _, length := range lengths {
		hex, err := generateRandomHex(length)
		if err != nil {
			t.Errorf("Failed to generate hex of length %d: %v", length, err)
			continue
		}
		if len(hex) != length {
			t.Errorf("Expected hex length %d, got %d", length, len(hex))
		}
		// Verify it's valid hex
		for _, char := range hex {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				t.Errorf("Invalid hex character '%c' in generated hex '%s'", char, hex)
				break
			}
		}
	}
}

func TestSHA256Verification(t *testing.T) {
	// Test the SHA-256 verification logic used in the solution validation
	salt := "abcd1234"
	target := "00"
	nonce := 0

	// Find a working nonce
	for nonce < 100000 {
		input := fmt.Sprintf("%s%d", salt, nonce)
		hash := sha256.Sum256([]byte(input))
		hashHex := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hashHex, target) {
			break
		}
		nonce++
	}

	if nonce >= 100000 {
		t.Skip("Could not find a solution within reasonable attempts")
		return
	}

	// Verify the solution works
	input := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(input))
	hashHex := hex.EncodeToString(hash[:])
	if !strings.HasPrefix(hashHex, target) {
		t.Errorf("Solution verification failed: hash %s does not start with %s", hashHex, target)
	}
}

func TestFileOperations(t *testing.T) {
	testFile := "./test_tokens_file.json"
	defer os.Remove(testFile) // Clean up

	cap := New(&CapConfig{
		TokensStorePath: testFile,
		NoFSState:       false,
	})

	// Add some tokens
	cap.config.State.TokensList["test1"] = time.Now().UnixMilli() + 60000
	cap.config.State.TokensList["test2"] = time.Now().UnixMilli() + 120000

	// Save tokens
	err := cap.saveTokens()
	if err != nil {
		t.Fatalf("Failed to save tokens: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("Tokens file was not created")
	}

	// Create new instance and load tokens
	cap2 := New(&CapConfig{
		TokensStorePath: testFile,
		NoFSState:       false,
	})

	if len(cap2.config.State.TokensList) != 2 {
		t.Errorf("Expected 2 loaded tokens, got %d", len(cap2.config.State.TokensList))
	}
	if _, exists := cap2.config.State.TokensList["test1"]; !exists {
		t.Error("Expected test1 token to be loaded")
	}
	if _, exists := cap2.config.State.TokensList["test2"]; !exists {
		t.Error("Expected test2 token to be loaded")
	}
}

func TestCleanup(t *testing.T) {
	testFile := "./test_cleanup_tokens.json"
	defer os.Remove(testFile) // Clean up

	cap := New(&CapConfig{
		TokensStorePath: testFile,
		NoFSState:       false,
	})

	// Add expired and valid tokens
	expiredTime := time.Now().UnixMilli() - 1000
	validTime := time.Now().UnixMilli() + 60000
	cap.config.State.TokensList["expired"] = expiredTime
	cap.config.State.TokensList["valid"] = validTime

	err := cap.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if len(cap.config.State.TokensList) != 1 {
		t.Errorf("Expected 1 token after cleanup, got %d", len(cap.config.State.TokensList))
	}
	if _, exists := cap.config.State.TokensList["valid"]; !exists {
		t.Error("Expected valid token to remain after cleanup")
	}
}

func BenchmarkCreateChallenge(b *testing.B) {
	cap := New(&CapConfig{NoFSState: true})
	config := &ChallengeConfig{
		ChallengeCount: 50,
		Store:          false, // Don't store for benchmark
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cap.CreateChallenge(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateRandomHex(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateRandomHex(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}
