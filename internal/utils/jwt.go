package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Token types
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeAdmin   = "admin"
	TokenTypeReset   = "reset"
	TokenTypeVerify  = "verify"
)

// Custom claims for JWT tokens
type CustomClaims struct {
	UserID      primitive.ObjectID `json:"user_id"`
	Username    string             `json:"username"`
	Email       string             `json:"email"`
	Role        string             `json:"role,omitempty"`
	TokenType   string             `json:"token_type"`
	Permissions []string           `json:"permissions,omitempty"`
	DeviceID    string             `json:"device_id,omitempty"`
	SessionID   string             `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

// AdminClaims for admin JWT tokens
type AdminClaims struct {
	AdminID     primitive.ObjectID `json:"admin_id"`
	Username    string             `json:"username"`
	Email       string             `json:"email"`
	Role        string             `json:"role"`
	Permissions []string           `json:"permissions"`
	TokenType   string             `json:"token_type"`
	SessionID   string             `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT operations
type JWTManager struct {
	secretKey      string
	adminSecretKey string
	accessExpiry   time.Duration
	refreshExpiry  time.Duration
	resetExpiry    time.Duration
	verifyExpiry   time.Duration
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey, adminSecretKey string, accessExpiry, refreshExpiry int64) *JWTManager {
	return &JWTManager{
		secretKey:      secretKey,
		adminSecretKey: adminSecretKey,
		accessExpiry:   time.Duration(accessExpiry) * time.Second,
		refreshExpiry:  time.Duration(refreshExpiry) * time.Second,
		resetExpiry:    time.Hour,      // 1 hour for password reset
		verifyExpiry:   24 * time.Hour, // 24 hours for email verification
	}
}

// GenerateAccessToken generates an access token for a user
func (j *JWTManager) GenerateAccessToken(userID primitive.ObjectID, username, email, deviceID, sessionID string) (string, error) {
	now := time.Now()
	claims := &CustomClaims{
		UserID:    userID,
		Username:  username,
		Email:     email,
		TokenType: TokenTypeAccess,
		DeviceID:  deviceID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "thread-app",
			Subject:   userID.Hex(),
			Audience:  []string{"thread-app-users"},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        primitive.NewObjectID().Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

// GenerateRefreshToken generates a refresh token for a user
func (j *JWTManager) GenerateRefreshToken(userID primitive.ObjectID, username, email, deviceID, sessionID string) (string, error) {
	now := time.Now()
	claims := &CustomClaims{
		UserID:    userID,
		Username:  username,
		Email:     email,
		TokenType: TokenTypeRefresh,
		DeviceID:  deviceID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "thread-app",
			Subject:   userID.Hex(),
			Audience:  []string{"thread-app-users"},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        primitive.NewObjectID().Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

// GenerateAdminToken generates an access token for admin users
func (j *JWTManager) GenerateAdminToken(adminID primitive.ObjectID, username, email, role string, permissions []string, sessionID string) (string, error) {
	now := time.Now()
	claims := &AdminClaims{
		AdminID:     adminID,
		Username:    username,
		Email:       email,
		Role:        role,
		Permissions: permissions,
		TokenType:   TokenTypeAdmin,
		SessionID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "thread-app",
			Subject:   adminID.Hex(),
			Audience:  []string{"thread-app-admin"},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        primitive.NewObjectID().Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.adminSecretKey))
}

// GenerateResetToken generates a password reset token
func (j *JWTManager) GenerateResetToken(userID primitive.ObjectID, email string) (string, error) {
	now := time.Now()
	claims := &CustomClaims{
		UserID:    userID,
		Email:     email,
		TokenType: TokenTypeReset,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "thread-app",
			Subject:   userID.Hex(),
			Audience:  []string{"thread-app-reset"},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.resetExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        primitive.NewObjectID().Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

// GenerateVerificationToken generates an email verification token
func (j *JWTManager) GenerateVerificationToken(userID primitive.ObjectID, email string) (string, error) {
	now := time.Now()
	claims := &CustomClaims{
		UserID:    userID,
		Email:     email,
		TokenType: TokenTypeVerify,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "thread-app",
			Subject:   userID.Hex(),
			Audience:  []string{"thread-app-verify"},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.verifyExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        primitive.NewObjectID().Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

// ValidateToken validates and parses a user token
func (j *JWTManager) ValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// ValidateAdminToken validates and parses an admin token
func (j *JWTManager) ValidateAdminToken(tokenString string) (*AdminClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.adminSecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse admin token: %w", err)
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid admin token")
	}

	return claims, nil
}

// RefreshTokens generates new access and refresh tokens
func (j *JWTManager) RefreshTokens(refreshToken string) (string, string, error) {
	claims, err := j.ValidateToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != TokenTypeRefresh {
		return "", "", errors.New("token is not a refresh token")
	}

	// Generate new tokens
	newAccessToken, err := j.GenerateAccessToken(claims.UserID, claims.Username, claims.Email, claims.DeviceID, claims.SessionID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := j.GenerateRefreshToken(claims.UserID, claims.Username, claims.Email, claims.DeviceID, claims.SessionID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}

// ExtractTokenFromHeader extracts token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	return authHeader[len(bearerPrefix):], nil
}

// GetTokenExpiry returns the expiry time for different token types
func (j *JWTManager) GetTokenExpiry(tokenType string) time.Duration {
	switch tokenType {
	case TokenTypeAccess:
		return j.accessExpiry
	case TokenTypeRefresh:
		return j.refreshExpiry
	case TokenTypeReset:
		return j.resetExpiry
	case TokenTypeVerify:
		return j.verifyExpiry
	default:
		return j.accessExpiry
	}
}
