package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Admin struct {
	ID           primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Username     string              `bson:"username" json:"username" validate:"required,min=3,max=30"`
	Email        string              `bson:"email" json:"email" validate:"required,email"`
	PasswordHash string              `bson:"password_hash" json:"-"`
	FullName     string              `bson:"full_name" json:"full_name"`
	Avatar       string              `bson:"avatar" json:"avatar"`
	Role         string              `bson:"role" json:"role"` // "super_admin", "admin", "moderator", "support"
	Permissions  []string            `bson:"permissions" json:"permissions"`
	IsActive     bool                `bson:"is_active" json:"is_active"`
	LastLoginAt  *time.Time          `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	LastLoginIP  string              `bson:"last_login_ip" json:"-"`
	CreatedBy    *primitive.ObjectID `bson:"created_by,omitempty" json:"created_by,omitempty"`
	CreatedAt    time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time           `bson:"updated_at" json:"updated_at"`
}

type AdminSession struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	AdminID   primitive.ObjectID `bson:"admin_id" json:"admin_id"`
	Token     string             `bson:"token" json:"token"`
	IPAddress string             `bson:"ip_address" json:"ip_address"`
	UserAgent string             `bson:"user_agent" json:"user_agent"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type AdminLog struct {
	ID         primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	AdminID    primitive.ObjectID     `bson:"admin_id" json:"admin_id"`
	Action     string                 `bson:"action" json:"action"`
	Resource   string                 `bson:"resource" json:"resource"` // "user", "thread", "report", "settings"
	ResourceID *primitive.ObjectID    `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	Details    map[string]interface{} `bson:"details" json:"details"`
	IPAddress  string                 `bson:"ip_address" json:"ip_address"`
	UserAgent  string                 `bson:"user_agent" json:"user_agent"`
	CreatedAt  time.Time              `bson:"created_at" json:"created_at"`

	// Populated fields
	Admin *Admin `bson:"-" json:"admin,omitempty"`
}

type SystemConfig struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Key             string             `bson:"key" json:"key" validate:"required"`
	Value           interface{}        `bson:"value" json:"value"`
	Type            string             `bson:"type" json:"type"` // "string", "number", "boolean", "object", "array"
	Description     string             `bson:"description" json:"description"`
	Category        string             `bson:"category" json:"category"` // "general", "security", "features", "limits", "storage"
	IsPublic        bool               `bson:"is_public" json:"is_public"`
	RequiresRestart bool               `bson:"requires_restart" json:"requires_restart"`
	ValidationRules []ValidationRule   `bson:"validation_rules" json:"validation_rules"`
	LastModifiedBy  primitive.ObjectID `bson:"last_modified_by" json:"last_modified_by"`
	CreatedAt       time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time          `bson:"updated_at" json:"updated_at"`
}

type ValidationRule struct {
	Type    string      `bson:"type" json:"type"` // "min", "max", "pattern", "required", "enum"
	Value   interface{} `bson:"value" json:"value"`
	Message string      `bson:"message" json:"message"`
}

type SystemStats struct {
	ID   primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Date time.Time          `bson:"date" json:"date"`

	// User metrics
	TotalUsers     int64 `bson:"total_users" json:"total_users"`
	ActiveUsers    int64 `bson:"active_users" json:"active_users"`
	NewUsers       int64 `bson:"new_users" json:"new_users"`
	VerifiedUsers  int64 `bson:"verified_users" json:"verified_users"`
	SuspendedUsers int64 `bson:"suspended_users" json:"suspended_users"`

	// Content metrics
	TotalThreads int64 `bson:"total_threads" json:"total_threads"`
	NewThreads   int64 `bson:"new_threads" json:"new_threads"`
	TotalReplies int64 `bson:"total_replies" json:"total_replies"`
	TotalLikes   int64 `bson:"total_likes" json:"total_likes"`
	TotalReposts int64 `bson:"total_reposts" json:"total_reposts"`
	TotalShares  int64 `bson:"total_shares" json:"total_shares"`

	// Message metrics
	TotalMessages      int64 `bson:"total_messages" json:"total_messages"`
	NewMessages        int64 `bson:"new_messages" json:"new_messages"`
	TotalConversations int64 `bson:"total_conversations" json:"total_conversations"`

	// System metrics
	TotalReports    int64 `bson:"total_reports" json:"total_reports"`
	PendingReports  int64 `bson:"pending_reports" json:"pending_reports"`
	ResolvedReports int64 `bson:"resolved_reports" json:"resolved_reports"`

	// Storage metrics
	TotalMediaFiles  int64 `bson:"total_media_files" json:"total_media_files"`
	TotalStorageUsed int64 `bson:"total_storage_used" json:"total_storage_used"` // bytes
	BandwidthUsed    int64 `bson:"bandwidth_used" json:"bandwidth_used"`         // bytes

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type ModerationAction struct {
	ID         primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	AdminID    primitive.ObjectID  `bson:"admin_id" json:"admin_id"`
	TargetType string              `bson:"target_type" json:"target_type"` // "user", "thread", "message"
	TargetID   primitive.ObjectID  `bson:"target_id" json:"target_id"`
	Action     string              `bson:"action" json:"action"` // "warn", "suspend", "ban", "delete", "hide", "feature"
	Reason     string              `bson:"reason" json:"reason"`
	Duration   *time.Duration      `bson:"duration,omitempty" json:"duration,omitempty"` // for temporary actions
	ExpiresAt  *time.Time          `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	IsActive   bool                `bson:"is_active" json:"is_active"`
	Notes      string              `bson:"notes" json:"notes"`
	ReportID   *primitive.ObjectID `bson:"report_id,omitempty" json:"report_id,omitempty"`
	CreatedAt  time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time           `bson:"updated_at" json:"updated_at"`

	// Populated fields
	Admin        *Admin  `bson:"-" json:"admin,omitempty"`
	TargetUser   *User   `bson:"-" json:"target_user,omitempty"`
	TargetThread *Thread `bson:"-" json:"target_thread,omitempty"`
}

type ContentFilter struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name" validate:"required"`
	Type        string             `bson:"type" json:"type"` // "keyword", "regex", "ai_model", "hash"
	Pattern     string             `bson:"pattern" json:"pattern"`
	Action      string             `bson:"action" json:"action"`         // "hide", "flag", "delete", "warn"
	Severity    string             `bson:"severity" json:"severity"`     // "low", "medium", "high", "critical"
	Categories  []string           `bson:"categories" json:"categories"` // "spam", "hate_speech", "violence", etc.
	IsActive    bool               `bson:"is_active" json:"is_active"`
	AutoApprove bool               `bson:"auto_approve" json:"auto_approve"`
	MatchCount  int64              `bson:"match_count" json:"match_count"`
	LastMatch   *time.Time         `bson:"last_match,omitempty" json:"last_match,omitempty"`
	CreatedBy   primitive.ObjectID `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

type AuditLog struct {
	ID         primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID     *primitive.ObjectID    `bson:"user_id,omitempty" json:"user_id,omitempty"`
	AdminID    *primitive.ObjectID    `bson:"admin_id,omitempty" json:"admin_id,omitempty"`
	Action     string                 `bson:"action" json:"action"`
	Resource   string                 `bson:"resource" json:"resource"`
	ResourceID *primitive.ObjectID    `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	OldValue   interface{}            `bson:"old_value,omitempty" json:"old_value,omitempty"`
	NewValue   interface{}            `bson:"new_value,omitempty" json:"new_value,omitempty"`
	IPAddress  string                 `bson:"ip_address" json:"ip_address"`
	UserAgent  string                 `bson:"user_agent" json:"user_agent"`
	Metadata   map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt  time.Time              `bson:"created_at" json:"created_at"`
}
