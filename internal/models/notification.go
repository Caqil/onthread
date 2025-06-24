package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Notification struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	RecipientID primitive.ObjectID   `bson:"recipient_id" json:"recipient_id"`
	ActorID     primitive.ObjectID   `bson:"actor_id" json:"actor_id"`
	Type        string               `bson:"type" json:"type"`               // "like", "reply", "repost", "quote", "follow", "mention", "dm", "thread_scheduled"
	TargetType  string               `bson:"target_type" json:"target_type"` // "thread", "user", "message"
	TargetID    *primitive.ObjectID  `bson:"target_id,omitempty" json:"target_id,omitempty"`
	ThreadID    *primitive.ObjectID  `bson:"thread_id,omitempty" json:"thread_id,omitempty"`
	Title       string               `bson:"title" json:"title"`
	Content     string               `bson:"content" json:"content"`
	ActionURL   string               `bson:"action_url" json:"action_url"`
	IsRead      bool                 `bson:"is_read" json:"is_read"`
	IsArchived  bool                 `bson:"is_archived" json:"is_archived"`
	Priority    string               `bson:"priority" json:"priority"` // "low", "normal", "high"
	Channel     []string             `bson:"channel" json:"channel"`   // "in_app", "push", "email"
	Metadata    NotificationMetadata `bson:"metadata" json:"metadata"`
	GroupID     *primitive.ObjectID  `bson:"group_id,omitempty" json:"group_id,omitempty"` // for grouping similar notifications
	ReadAt      *time.Time           `bson:"read_at,omitempty" json:"read_at,omitempty"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`

	// Populated fields
	Actor      *User   `bson:"-" json:"actor,omitempty"`
	Thread     *Thread `bson:"-" json:"thread,omitempty"`
	TargetUser *User   `bson:"-" json:"target_user,omitempty"`
}

type NotificationMetadata struct {
	DeviceToken string                 `bson:"device_token,omitempty" json:"device_token,omitempty"`
	Platform    string                 `bson:"platform,omitempty" json:"platform,omitempty"` // "ios", "android", "web"
	AppVersion  string                 `bson:"app_version,omitempty" json:"app_version,omitempty"`
	CustomData  map[string]interface{} `bson:"custom_data,omitempty" json:"custom_data,omitempty"`
	SentAt      *time.Time             `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
	DeliveredAt *time.Time             `bson:"delivered_at,omitempty" json:"delivered_at,omitempty"`
	ClickedAt   *time.Time             `bson:"clicked_at,omitempty" json:"clicked_at,omitempty"`
}

type NotificationGroup struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RecipientID        primitive.ObjectID `bson:"recipient_id" json:"recipient_id"`
	Type               string             `bson:"type" json:"type"`
	Count              int64              `bson:"count" json:"count"`
	LastActorID        primitive.ObjectID `bson:"last_actor_id" json:"last_actor_id"`
	LastNotificationID primitive.ObjectID `bson:"last_notification_id" json:"last_notification_id"`
	IsRead             bool               `bson:"is_read" json:"is_read"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
}

type NotificationSettings struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	PushEnabled  bool               `bson:"push_enabled" json:"push_enabled"`
	EmailEnabled bool               `bson:"email_enabled" json:"email_enabled"`
	InAppEnabled bool               `bson:"in_app_enabled" json:"in_app_enabled"`

	// Notification types
	Likes            bool `bson:"likes" json:"likes"`
	Replies          bool `bson:"replies" json:"replies"`
	Reposts          bool `bson:"reposts" json:"reposts"`
	Quotes           bool `bson:"quotes" json:"quotes"`
	Follows          bool `bson:"follows" json:"follows"`
	Mentions         bool `bson:"mentions" json:"mentions"`
	DirectMessages   bool `bson:"direct_messages" json:"direct_messages"`
	ScheduledThreads bool `bson:"scheduled_threads" json:"scheduled_threads"`

	// Advanced settings
	OnlyFromFollowing bool   `bson:"only_from_following" json:"only_from_following"`
	QuietHoursEnabled bool   `bson:"quiet_hours_enabled" json:"quiet_hours_enabled"`
	QuietHoursStart   string `bson:"quiet_hours_start" json:"quiet_hours_start"` // "22:00"
	QuietHoursEnd     string `bson:"quiet_hours_end" json:"quiet_hours_end"`     // "08:00"
	Timezone          string `bson:"timezone" json:"timezone"`

	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type EmailQueue struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	RecipientID primitive.ObjectID     `bson:"recipient_id" json:"recipient_id"`
	Email       string                 `bson:"email" json:"email"`
	Subject     string                 `bson:"subject" json:"subject"`
	Body        string                 `bson:"body" json:"body"`
	Template    string                 `bson:"template" json:"template"`
	Data        map[string]interface{} `bson:"data" json:"data"`
	Status      string                 `bson:"status" json:"status"`     // "pending", "sent", "failed", "cancelled"
	Priority    string                 `bson:"priority" json:"priority"` // "low", "normal", "high"
	Attempts    int                    `bson:"attempts" json:"attempts"`
	MaxAttempts int                    `bson:"max_attempts" json:"max_attempts"`
	Error       string                 `bson:"error" json:"error"`
	ScheduledAt time.Time              `bson:"scheduled_at" json:"scheduled_at"`
	SentAt      *time.Time             `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time              `bson:"updated_at" json:"updated_at"`
}
