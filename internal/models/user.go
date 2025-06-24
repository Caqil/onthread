package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username       string             `bson:"username" json:"username" validate:"required,min=3,max=30"`
	Email          string             `bson:"email" json:"email" validate:"required,email"`
	PasswordHash   string             `bson:"password_hash" json:"-"`
	DisplayName    string             `bson:"display_name" json:"display_name"`
	Bio            string             `bson:"bio" json:"bio" validate:"max=500"`
	ProfilePicture string             `bson:"profile_picture" json:"profile_picture"`
	CoverImage     string             `bson:"cover_image" json:"cover_image"`
	IsVerified     bool               `bson:"is_verified" json:"is_verified"`
	IsPrivate      bool               `bson:"is_private" json:"is_private"`
	IsActive       bool               `bson:"is_active" json:"is_active"`
	IsSuspended    bool               `bson:"is_suspended" json:"is_suspended"`
	FollowersCount int64              `bson:"followers_count" json:"followers_count"`
	FollowingCount int64              `bson:"following_count" json:"following_count"`
	ThreadsCount   int64              `bson:"threads_count" json:"threads_count"`
	Location       string             `bson:"location" json:"location"`
	Website        string             `bson:"website" json:"website"`
	BirthDate      *time.Time         `bson:"birth_date" json:"birth_date"`
	JoinedAt       time.Time          `bson:"joined_at" json:"joined_at"`
	LastActiveAt   time.Time          `bson:"last_active_at" json:"last_active_at"`
	Settings       UserSettings       `bson:"settings" json:"settings"`
	DeviceTokens   []string           `bson:"device_tokens" json:"-"`
	Metadata       UserMetadata       `bson:"metadata" json:"metadata"`
	Badges         []Badge            `bson:"badges" json:"badges"`
	Links          []UserLink         `bson:"links" json:"links"`
}

type UserSettings struct {
	Language             string   `bson:"language" json:"language"`
	Theme                string   `bson:"theme" json:"theme"` // "light", "dark", "auto"
	EmailNotifications   bool     `bson:"email_notifications" json:"email_notifications"`
	PushNotifications    bool     `bson:"push_notifications" json:"push_notifications"`
	ShowActivity         bool     `bson:"show_activity" json:"show_activity"`
	AllowMessageRequests bool     `bson:"allow_message_requests" json:"allow_message_requests"`
	ShowReadReceipts     bool     `bson:"show_read_receipts" json:"show_read_receipts"`
	AllowTagging         bool     `bson:"allow_tagging" json:"allow_tagging"`
	ContentLanguages     []string `bson:"content_languages" json:"content_languages"`
	SensitiveContent     bool     `bson:"sensitive_content" json:"sensitive_content"`
	DataSaver            bool     `bson:"data_saver" json:"data_saver"`
}

type UserMetadata struct {
	LastLoginIP         string     `bson:"last_login_ip" json:"-"`
	LoginCount          int64      `bson:"login_count" json:"-"`
	RegistrationIP      string     `bson:"registration_ip" json:"-"`
	TwoFactorEnabled    bool       `bson:"two_factor_enabled" json:"-"`
	PhoneNumber         string     `bson:"phone_number" json:"-"`
	PhoneVerified       bool       `bson:"phone_verified" json:"-"`
	EmailVerified       bool       `bson:"email_verified" json:"email_verified"`
	VerificationToken   string     `bson:"verification_token" json:"-"`
	PasswordResetToken  string     `bson:"password_reset_token" json:"-"`
	PasswordResetExpiry *time.Time `bson:"password_reset_expiry" json:"-"`
}

type Badge struct {
	Type        string    `bson:"type" json:"type"` // "verified", "early_adopter", "developer", etc.
	Name        string    `bson:"name" json:"name"`
	Icon        string    `bson:"icon" json:"icon"`
	Color       string    `bson:"color" json:"color"`
	Description string    `bson:"description" json:"description"`
	AwardedAt   time.Time `bson:"awarded_at" json:"awarded_at"`
}

type UserLink struct {
	Title string `bson:"title" json:"title"`
	URL   string `bson:"url" json:"url"`
	Icon  string `bson:"icon" json:"icon"`
}

type Follow struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FollowerID primitive.ObjectID `bson:"follower_id" json:"follower_id"`
	FollowedID primitive.ObjectID `bson:"followed_id" json:"followed_id"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	IsAccepted bool               `bson:"is_accepted" json:"is_accepted"`
	IsMuted    bool               `bson:"is_muted" json:"is_muted"`
}

type Block struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	BlockerID primitive.ObjectID `bson:"blocker_id" json:"blocker_id"`
	BlockedID primitive.ObjectID `bson:"blocked_id" json:"blocked_id"`
	Reason    string             `bson:"reason" json:"reason"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type Mute struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	MutedID   primitive.ObjectID `bson:"muted_id" json:"muted_id"`
	Duration  *time.Time         `bson:"duration,omitempty" json:"duration,omitempty"` // nil for permanent
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}
