package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/repository"
	"onthread/internal/utils"
	"onthread/pkg/logger"
)

// AuthMiddleware handles user authentication and authorization
type AuthMiddleware struct {
	jwtManager *utils.JWTManager
	userRepo   repository.UserRepository
}

// NewAuthMiddleware creates a new auth middleware instance
func NewAuthMiddleware(jwtManager *utils.JWTManager, userRepo repository.UserRepository) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		userRepo:   userRepo,
	}
}

// RequireAuth middleware that requires user authentication
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			utils.Unauthorized(c, "Authorization required")
			c.Abort()
			return
		}

		// Extract token from Bearer format
		tokenString, err := utils.ExtractTokenFromHeader(token)
		if err != nil {
			utils.Unauthorized(c, "Invalid authorization format")
			c.Abort()
			return
		}

		// Verify token
		claims, err := m.jwtManager.ValidateToken(tokenString)
		if err != nil {
			utils.Unauthorized(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Get user ID from claims
		userID := claims.UserID

		// Get user from database
		user, err := m.userRepo.GetByID(c.Request.Context(), userID)
		if err != nil {
			utils.Unauthorized(c, "User not found")
			c.Abort()
			return
		}

		// Check if user is active
		if !user.IsActive {
			utils.Forbidden(c, "Account is disabled")
			c.Abort()
			return
		}

		// Check if email is verified (if required)
		if !user.Metadata.EmailVerified && m.requireEmailVerification(c.Request.URL.Path) {
			utils.Forbidden(c, "Email verification required")
			c.Abort()
			return
		}

		// Check if account is suspended
		if user.IsSuspended {
			utils.Forbidden(c, "Account is suspended")
			c.Abort()
			return
		}

		// Update last activity
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			m.userRepo.UpdateLastActivity(ctx, userID)
		}()

		// Add user info to context
		c.Set("user_id", userID)
		c.Set("user", user)
		c.Set("user_role", user.Role)

		// Add to request context for logging
		ctx := logger.NewContextWithUserID(c.Request.Context(), userID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// OptionalAuth middleware that optionally authenticates users
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.Next()
			return
		}

		// Extract token from Bearer format
		tokenString, err := utils.ExtractTokenFromHeader(token)
		if err != nil {
			c.Next()
			return
		}

		// Verify token
		claims, err := m.jwtManager.ValidateToken(tokenString)
		if err != nil {
			c.Next()
			return
		}

		// Get user ID from claims
		userID := claims.UserID

		// Get user from database
		user, err := m.userRepo.GetByID(c.Request.Context(), userID)
		if err != nil {
			c.Next()
			return
		}

		// Check if user is active
		if !user.IsActive || user.IsSuspended {
			c.Next()
			return
		}

		// Add user info to context
		c.Set("user_id", userID)
		c.Set("user", user)
		c.Set("user_role", user.Role)

		// Add to request context for logging
		ctx := logger.NewContextWithUserID(c.Request.Context(), userID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequireEmailVerified middleware that requires email verification
func (m *AuthMiddleware) RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			utils.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		userData := user.(*models.User)
		if !userData.Metadata.EmailVerified {
			utils.Forbidden(c, "Email verification required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires specific user role
func (m *AuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			utils.Forbidden(c, "User role not found")
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			utils.Forbidden(c, "Invalid user role format")
			c.Abort()
			return
		}

		if roleStr != role {
			utils.Forbidden(c, "Insufficient privileges")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireOwnership middleware that checks if user owns the resource
func (m *AuthMiddleware) RequireOwnership(paramName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			utils.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		resourceUserID := c.Param(paramName)
		if resourceUserID == "" {
			utils.BadRequest(c, "Resource user ID required")
			c.Abort()
			return
		}

		// Convert to ObjectID for comparison
		currentUserID := userID.(primitive.ObjectID)
		resourceObjID, err := primitive.ObjectIDFromHex(resourceUserID)
		if err != nil {
			utils.BadRequest(c, "Invalid resource user ID")
			c.Abort()
			return
		}

		if currentUserID != resourceObjID {
			utils.Forbidden(c, "Access denied: insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireVerified2FA middleware that requires 2FA verification
func (m *AuthMiddleware) RequireVerified2FA() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			utils.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		userData := user.(*models.User)
		if userData.Metadata.TwoFactorEnabled {
			// Check if 2FA is verified in this session
			// This would typically be stored in session or separate verification token
			twoFAVerified := c.GetHeader("X-2FA-Verified") // Or check session/Redis
			if twoFAVerified != "true" {
				utils.Forbidden(c, "Two-factor authentication required")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// ValidateSession middleware that validates session information
func (m *AuthMiddleware) ValidateSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.GetHeader("X-Session-ID")
		if sessionID == "" {
			c.Next()
			return
		}

		userID, exists := c.Get("user_id")
		if !exists {
			c.Next()
			return
		}

		// Validate session exists and is active
		isValid, err := m.userRepo.ValidateSession(c.Request.Context(), userID.(primitive.ObjectID), sessionID)
		if err != nil || !isValid {
			utils.Unauthorized(c, "Invalid session")
			c.Abort()
			return
		}

		// Add session info to context
		c.Set("session_id", sessionID)
		ctx := logger.NewContextWithSessionID(c.Request.Context(), sessionID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// SecurityHeaders middleware adds security headers
func (m *AuthMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Anti-clickjacking
		c.Header("X-Frame-Options", "DENY")

		// XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Content type sniffing prevention
		c.Header("X-Content-Type-Options", "nosniff")

		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy (adjust based on your needs)
		c.Header("Content-Security-Policy", "default-src 'self'")

		c.Next()
	}
}

// Helper functions

// requireEmailVerification checks if the endpoint requires email verification
func (m *AuthMiddleware) requireEmailVerification(path string) bool {
	// Define paths that don't require email verification
	exemptPaths := []string{
		"/api/auth/verify-email",
		"/api/auth/resend-verification",
		"/api/auth/logout",
		"/api/auth/me",
	}

	for _, exemptPath := range exemptPaths {
		if strings.HasPrefix(path, exemptPath) {
			return false
		}
	}

	return true
}
