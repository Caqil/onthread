package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

const (
	// Bcrypt cost - adjust based on your security requirements and server performance
	BcryptCost = 12

	// Scrypt parameters
	ScryptN       = 32768
	ScryptR       = 8
	ScryptP       = 1
	ScryptKeyLen  = 64
	ScryptSaltLen = 32
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(bytes), nil
}

// CheckPassword verifies a password against its hash using bcrypt
func CheckPassword(password, hash string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}
	if hash == "" {
		return errors.New("hash cannot be empty")
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IsValidPassword checks if a password meets security requirements
func IsValidPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return errors.New("password must not exceed 128 characters")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// Advanced password hashing using scrypt (alternative to bcrypt)
func HashPasswordScrypt(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate random salt
	salt := make([]byte, ScryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate hash
	hash, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Encode salt and hash
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", ScryptN, ScryptR, ScryptP, saltB64, hashB64), nil
}

// CheckPasswordScrypt verifies a password against its scrypt hash
func CheckPasswordScrypt(password, hashedPassword string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}
	if hashedPassword == "" {
		return errors.New("hash cannot be empty")
	}

	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return errors.New("invalid hash format")
	}

	// Parse parameters (parts[1], parts[2], parts[3] are N, r, p)
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	expectedHash, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	// Generate hash with provided password
	hash, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Compare hashes using constant-time comparison
	if subtle.ConstantTimeCompare(hash, expectedHash) != 1 {
		return errors.New("password does not match")
	}

	return nil
}

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSecureID generates a secure random ID (useful for verification tokens, etc.)
func GenerateSecureID() (string, error) {
	return GenerateRandomToken(32)
}

// PasswordStrength calculates password strength score (0-100)
func PasswordStrength(password string) int {
	if password == "" {
		return 0
	}

	score := 0

	// Length score
	length := len(password)
	switch {
	case length >= 12:
		score += 25
	case length >= 10:
		score += 20
	case length >= 8:
		score += 15
	case length >= 6:
		score += 10
	default:
		score += 5
	}

	// Character variety score
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if hasUpper {
		score += 15
	}
	if hasLower {
		score += 15
	}
	if hasDigit {
		score += 15
	}
	if hasSpecial {
		score += 30
	}

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}

	return score
}
