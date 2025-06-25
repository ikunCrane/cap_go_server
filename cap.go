package capserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ChallengeTuple represents a single challenge consisting of salt and target
type ChallengeTuple [2]string

// ChallengeData contains the complete challenge information
type ChallengeData struct {
	Challenge []ChallengeTuple `json:"challenge"`
	Expires   int64            `json:"expires"`
	Token     string           `json:"token"`
}

// ChallengeState represents the internal state of challenges and tokens
type ChallengeState struct {
	ChallengesList map[string]*ChallengeData `json:"challengesList"`
	TokensList     map[string]int64          `json:"tokensList"`
}

// ChallengeConfig contains configuration options for challenge generation
type ChallengeConfig struct {
	ChallengeCount      int  `json:"challengeCount,omitempty"`      // Number of challenges to generate (default: 50)
	ChallengeSize       int  `json:"challengeSize,omitempty"`       // Size of each challenge in bytes (default: 32)
	ChallengeDifficulty int  `json:"challengeDifficulty,omitempty"` // Difficulty level (default: 4)
	ExpiresMs           int  `json:"expiresMs,omitempty"`           // Expiration time in milliseconds (default: 600000)
	Store               bool `json:"store,omitempty"`               // Whether to store the challenge in memory (default: true)
}

// TokenConfig contains configuration options for token validation
type TokenConfig struct {
	KeepToken bool `json:"keepToken,omitempty"` // Whether to keep the token after validation
}

// Solution represents a solution to a challenge
type Solution struct {
	Token     string          `json:"token"`
	Solutions [][]interface{} `json:"solutions"` // Array of [salt, target, solution] tuples
}

// CapConfig contains the main configuration for the Cap instance
type CapConfig struct {
	TokensStorePath string          `json:"tokensStorePath,omitempty"` // Path to store tokens file
	State           *ChallengeState `json:"state,omitempty"`           // State configuration
	NoFSState       bool            `json:"noFSState,omitempty"`       // Whether to disable file-based state storage
}

// ChallengeResponse represents the response from CreateChallenge
type ChallengeResponse struct {
	Challenge []ChallengeTuple `json:"challenge"`
	Token     string           `json:"token,omitempty"`
	Expires   int64            `json:"expires"`
}

// RedeemResponse represents the response from RedeemChallenge
type RedeemResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// ValidationResponse represents the response from ValidateToken
type ValidationResponse struct {
	Success bool `json:"success"`
}

// Cap represents the main Cap instance
type Cap struct {
	config *CapConfig
	mu     sync.RWMutex
}

const (
	DefaultTokensStore         = ".data/tokensList.json"
	DefaultChallengeCount      = 50
	DefaultChallengeSize       = 32
	DefaultChallengeDifficulty = 4
	DefaultExpiresMs           = 600000  // 10 minutes
	DefaultTokenExpiresMs      = 1200000 // 20 minutes
)

// New creates a new Cap instance with the given configuration
func New(configObj *CapConfig) *Cap {
	config := &CapConfig{
		TokensStorePath: DefaultTokensStore,
		NoFSState:       false,
		State: &ChallengeState{
			ChallengesList: make(map[string]*ChallengeData),
			TokensList:     make(map[string]int64),
		},
	}

	if configObj != nil {
		if configObj.TokensStorePath != "" {
			config.TokensStorePath = configObj.TokensStorePath
		}
		if configObj.NoFSState {
			config.NoFSState = configObj.NoFSState
		}
		if configObj.State != nil {
			config.State = configObj.State
		}
	}

	cap := &Cap{
		config: config,
	}

	if !config.NoFSState {
		cap.loadTokens()
	}

	return cap
}

// CreateChallenge generates a new challenge with the specified configuration
func (c *Cap) CreateChallenge(conf *ChallengeConfig) (*ChallengeResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanExpiredTokens()

	// Set default values
	challengeCount := DefaultChallengeCount
	challengeSize := DefaultChallengeSize
	challengeDifficulty := DefaultChallengeDifficulty
	expiresMs := DefaultExpiresMs
	store := true

	if conf != nil {
		if conf.ChallengeCount > 0 {
			challengeCount = conf.ChallengeCount
		}
		if conf.ChallengeSize > 0 {
			challengeSize = conf.ChallengeSize
		}
		if conf.ChallengeDifficulty > 0 {
			challengeDifficulty = conf.ChallengeDifficulty
		}
		if conf.ExpiresMs > 0 {
			expiresMs = conf.ExpiresMs
		}
		store = conf.Store
	}

	// Generate challenges
	challenges := make([]ChallengeTuple, challengeCount)
	for i := 0; i < challengeCount; i++ {
		salt, err := generateRandomHex(challengeSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}

		target, err := generateRandomHex(challengeDifficulty)
		if err != nil {
			return nil, fmt.Errorf("failed to generate target: %w", err)
		}

		challenges[i] = ChallengeTuple{salt, target}
	}

	token, err := generateRandomHex(50) // 25 bytes = 50 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	expires := time.Now().UnixMilli() + int64(expiresMs)

	if !store {
		return &ChallengeResponse{
			Challenge: challenges,
			Expires:   expires,
		}, nil
	}

	c.config.State.ChallengesList[token] = &ChallengeData{
		Challenge: challenges,
		Expires:   expires,
		Token:     token,
	}

	return &ChallengeResponse{
		Challenge: challenges,
		Token:     token,
		Expires:   expires,
	}, nil
}

// RedeemChallenge validates a challenge solution and returns a verification token
func (c *Cap) RedeemChallenge(solution *Solution) (*RedeemResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if solution == nil || solution.Token == "" || solution.Solutions == nil {
		return &RedeemResponse{
			Success: false,
			Message: "Invalid body",
		}, nil
	}

	c.cleanExpiredTokens()

	challengeData, exists := c.config.State.ChallengesList[solution.Token]
	if !exists || challengeData.Expires < time.Now().UnixMilli() {
		delete(c.config.State.ChallengesList, solution.Token)
		return &RedeemResponse{
			Success: false,
			Message: "Challenge expired",
		}, nil
	}

	delete(c.config.State.ChallengesList, solution.Token)

	// Validate all challenges
	for _, challenge := range challengeData.Challenge {
		salt, target := challenge[0], challenge[1]
		found := false

		for _, sol := range solution.Solutions {
			if len(sol) != 3 {
				continue
			}

			solSalt, ok1 := sol[0].(string)
			solTarget, ok2 := sol[1].(string)
			solValue := sol[2]

			if !ok1 || !ok2 || solSalt != salt || solTarget != target {
				continue
			}

			// Convert solution value to string
			var solStr string
			switch v := solValue.(type) {
			case string:
				solStr = v
			case float64:
				solStr = fmt.Sprintf("%.0f", v)
			case int:
				solStr = fmt.Sprintf("%d", v)
			default:
				solStr = fmt.Sprintf("%v", v)
			}

			// Verify the solution
			hash := sha256.Sum256([]byte(salt + solStr))
			hashHex := hex.EncodeToString(hash[:])

			if strings.HasPrefix(hashHex, target) {
				found = true
				break
			}
		}

		if !found {
			return &RedeemResponse{
				Success: false,
				Message: "Invalid solution",
			}, nil
		}
	}

	// Generate verification token
	vertoken, err := generateRandomHex(30) // 15 bytes = 30 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	expires := time.Now().UnixMilli() + DefaultTokenExpiresMs
	hash := sha256.Sum256([]byte(vertoken))
	hashHex := hex.EncodeToString(hash[:])

	id, err := generateRandomHex(16) // 8 bytes = 16 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	key := fmt.Sprintf("%s:%s", id, hashHex)
	c.config.State.TokensList[key] = expires

	if !c.config.NoFSState {
		if err := c.saveTokens(); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Warning: failed to save tokens: %v\n", err)
		}
	}

	return &RedeemResponse{
		Success: true,
		Token:   fmt.Sprintf("%s:%s", id, vertoken),
		Expires: expires,
	}, nil
}

// ValidateToken validates a verification token
func (c *Cap) ValidateToken(token string, conf *TokenConfig) (*ValidationResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanExpiredTokens()

	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return &ValidationResponse{Success: false}, nil
	}

	id, vertoken := parts[0], parts[1]
	hash := sha256.Sum256([]byte(vertoken))
	hashHex := hex.EncodeToString(hash[:])
	key := fmt.Sprintf("%s:%s", id, hashHex)

	if _, exists := c.config.State.TokensList[key]; exists {
		if conf == nil || !conf.KeepToken {
			delete(c.config.State.TokensList, key)
		}

		if !c.config.NoFSState {
			if err := c.saveTokens(); err != nil {
				// Log error but don't fail the operation
				fmt.Printf("Warning: failed to save tokens: %v\n", err)
			}
		}

		return &ValidationResponse{Success: true}, nil
	}

	return &ValidationResponse{Success: false}, nil
}

// Cleanup cleans up expired tokens and syncs state to disk
func (c *Cap) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokensChanged := c.cleanExpiredTokens()

	if tokensChanged && !c.config.NoFSState {
		return c.saveTokens()
	}

	return nil
}

// loadTokens loads tokens from the storage file
func (c *Cap) loadTokens() {
	dirPath := filepath.Dir(c.config.TokensStorePath)
	if dirPath != "." {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			fmt.Printf("Warning: couldn't create tokens directory: %v\n", err)
			return
		}
	}

	data, err := os.ReadFile(c.config.TokensStorePath)
	if err != nil {
		// File doesn't exist, create empty one
		fmt.Printf("[cap] Tokens file not found, creating a new empty one\n")
		if err := os.WriteFile(c.config.TokensStorePath, []byte("{}"), 0644); err != nil {
			fmt.Printf("Warning: couldn't create tokens file: %v\n", err)
		}
		c.config.State.TokensList = make(map[string]int64)
		return
	}

	var tokensList map[string]int64
	if err := json.Unmarshal(data, &tokensList); err != nil {
		fmt.Printf("Warning: couldn't parse tokens file, using empty state: %v\n", err)
		c.config.State.TokensList = make(map[string]int64)
		return
	}

	c.config.State.TokensList = tokensList
	c.cleanExpiredTokens()
}

// saveTokens saves tokens to the storage file
func (c *Cap) saveTokens() error {
	data, err := json.Marshal(c.config.State.TokensList)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	return os.WriteFile(c.config.TokensStorePath, data, 0644)
}

// cleanExpiredTokens removes expired tokens and challenges from memory
func (c *Cap) cleanExpiredTokens() bool {
	now := time.Now().UnixMilli()
	tokensChanged := false

	// Clean expired challenges
	for k, v := range c.config.State.ChallengesList {
		if v.Expires < now {
			delete(c.config.State.ChallengesList, k)
		}
	}

	// Clean expired tokens
	for k, v := range c.config.State.TokensList {
		if v < now {
			delete(c.config.State.TokensList, k)
			tokensChanged = true
		}
	}

	return tokensChanged
}

// generateRandomHex generates a random hex string of the specified length
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}
