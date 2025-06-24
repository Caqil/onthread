package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/repository"
	"onthread/internal/utils"
	"onthread/pkg/logger"
)

// AdminMiddleware handles admin authentication and authorization
type AdminMiddleware struct {
	jwtManager *utils.JWTManager
	adminRepo  repository.AdminRepository
}

// NewAdminMiddleware creates a new admin middleware instance
func NewAdminMiddleware(jwtManager *utils.JWTManager, adminRepo repository.AdminRepository) *AdminMiddleware {
	return &AdminMiddleware{
		jwtManager: jwtManager,
		adminRepo:  adminRepo,
	}
}

// RequireAdmin middleware that requires admin authentication
func (m *AdminMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			utils.Unauthorized(c, "Admin authorization required")
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

		// Verify admin token
		claims, err := m.jwtManager.ValidateAdminToken(tokenString)
		if err != nil {
			utils.Unauthorized(c, "Invalid or expired admin token")
			c.Abort()
			return
		}

		// Get admin ID from claims
		adminID := claims.AdminID

		// Verify admin exists and is active
		admin, err := m.adminRepo.GetByID(c.Request.Context(), adminID)
		if err != nil {
			utils.Unauthorized(c, "Admin not found")
			c.Abort()
			return
		}

		if !admin.IsActive {
			utils.Forbidden(c, "Admin account is disabled")
			c.Abort()
			return
		}

		// Update last activity
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			m.adminRepo.UpdateLastActivity(ctx, adminID)
		}()

		// Add admin info to context
		c.Set("admin_id", adminID)
		c.Set("admin", admin)
		c.Set("admin_role", admin.Role)
		c.Set("admin_permissions", admin.Permissions)

		// Add to request context for logging
		ctx := logger.NewContextWithAdminID(c.Request.Context(), adminID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RequirePermission middleware that requires specific admin permission
func (m *AdminMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("admin_permissions")
		if !exists {
			utils.Forbidden(c, "Admin permissions not found")
			c.Abort()
			return
		}

		adminPermissions, ok := permissions.([]string)
		if !ok {
			utils.Forbidden(c, "Invalid admin permissions format")
			c.Abort()
			return
		}

		// Check if admin has the required permission or is super admin
		hasPermission := false
		for _, perm := range adminPermissions {
			if perm == permission || perm == "super_admin" {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			utils.Forbidden(c, "Insufficient admin permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires specific admin role
func (m *AdminMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		adminRole, exists := c.Get("admin_role")
		if !exists {
			utils.Forbidden(c, "Admin role not found")
			c.Abort()
			return
		}

		roleStr, ok := adminRole.(string)
		if !ok {
			utils.Forbidden(c, "Invalid admin role format")
			c.Abort()
			return
		}

		// Check role hierarchy: super_admin > admin > moderator
		allowedRoles := getRoleHierarchy(role)
		roleAllowed := false
		for _, allowedRole := range allowedRoles {
			if roleStr == allowedRole {
				roleAllowed = true
				break
			}
		}

		if !roleAllowed {
			utils.Forbidden(c, "Insufficient admin role")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireSuperAdmin middleware that requires super admin role
func (m *AdminMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return m.RequireRole("super_admin")
}

// RequireModerator middleware that requires at least moderator role
func (m *AdminMiddleware) RequireModerator() gin.HandlerFunc {
	return m.RequireRole("moderator")
}

// AuditLog middleware that logs admin actions
func (m *AdminMiddleware) AuditLog(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Log after request completion
		adminID, exists := c.Get("admin_id")
		if !exists {
			return
		}

		duration := time.Since(start)
		status := c.Writer.Status()

		// Extract resource info from URL
		resourceType, resourceID := extractResourceInfo(c.Request.URL.Path)

		// Log the admin action
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			auditLog := &struct {
				AdminID      primitive.ObjectID `bson:"admin_id"`
				Action       string             `bson:"action"`
				ResourceType string             `bson:"resource_type,omitempty"`
				ResourceID   string             `bson:"resource_id,omitempty"`
				Method       string             `bson:"method"`
				Path         string             `bson:"path"`
				StatusCode   int                `bson:"status_code"`
				Duration     int64              `bson:"duration_ms"`
				UserAgent    string             `bson:"user_agent,omitempty"`
				IPAddress    string             `bson:"ip_address,omitempty"`
				Timestamp    time.Time          `bson:"timestamp"`
			}{
				AdminID:      adminID.(primitive.ObjectID),
				Action:       action,
				ResourceType: resourceType,
				ResourceID:   resourceID,
				Method:       c.Request.Method,
				Path:         c.Request.URL.Path,
				StatusCode:   status,
				Duration:     duration.Milliseconds(),
				UserAgent:    c.GetHeader("User-Agent"),
				IPAddress:    c.ClientIP(),
				Timestamp:    time.Now(),
			}

			// Log to database (implement based on your audit log repository)
			logger.WithContext(ctx).WithFields(logrus.Fields{
				"admin_id":      auditLog.AdminID.Hex(),
				"action":        auditLog.Action,
				"resource_type": auditLog.ResourceType,
				"resource_id":   auditLog.ResourceID,
				"method":        auditLog.Method,
				"path":          auditLog.Path,
				"status_code":   auditLog.StatusCode,
				"duration_ms":   auditLog.Duration,
				"ip_address":    auditLog.IPAddress,
			}).Info("Admin action audited")
		}()
	}
}

// Helper functions

// getRoleHierarchy returns allowed roles based on hierarchy
func getRoleHierarchy(requiredRole string) []string {
	switch requiredRole {
	case "super_admin":
		return []string{"super_admin"}
	case "admin":
		return []string{"super_admin", "admin"}
	case "moderator":
		return []string{"super_admin", "admin", "moderator"}
	default:
		return []string{}
	}
}

// extractResourceInfo extracts resource type and ID from URL path
func extractResourceInfo(path string) (resourceType, resourceID string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// Parse common admin API patterns
	if len(parts) >= 2 && parts[0] == "admin" {
		if len(parts) >= 3 {
			resourceType = parts[1]
			if len(parts) >= 4 {
				resourceID = parts[2]
			}
		}
	}

	return resourceType, resourceID
}
