package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Conversation struct {
	ID            primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Type          string               `bson:"type" json:"type"` // "direct", "group"
	Participants  []primitive.ObjectID `bson:"participants" json:"participants"`
	CreatorID     primitive.ObjectID   `bson:"creator_id" json:"creator_id"`
	Title         string               `bson:"title" json:"title"` // for group conversations
	Description   string               `bson:"description" json:"description"`
	Avatar        string               `bson:"avatar" json:"avatar"`
	IsActive      bool                 `bson:"is_active" json:"is_active"`
	LastMessageID *primitive.ObjectID  `bson:"last_message_id,omitempty" json:"last_message_id,omitempty"`
	LastMessageAt *time.Time           `bson:"last_message_at,omitempty" json:"last_message_at,omitempty"`
	MessagesCount int64                `bson:"messages_count" json:"messages_count"`
	Settings      ConversationSettings `bson:"settings" json:"settings"`
	CreatedAt     time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time            `bson:"updated_at" json:"updated_at"`

	// Populated fields
	LastMessage       *Message `bson:"-" json:"last_message,omitempty"`
	OtherParticipants []User   `bson:"-" json:"other_participants,omitempty"`
	UnreadCount       int64    `bson:"-" json:"unread_count"`
	IsMuted           bool     `bson:"-" json:"is_muted"`
}

type ConversationSettings struct {
	AllowAddMembers      bool  `bson:"allow_add_members" json:"allow_add_members"`
	AllowEditInfo        bool  `bson:"allow_edit_info" json:"allow_edit_info"`
	OnlyAdminsCanPost    bool  `bson:"only_admins_can_post" json:"only_admins_can_post"`
	DisappearingMessages bool  `bson:"disappearing_messages" json:"disappearing_messages"`
	DisappearingDuration int64 `bson:"disappearing_duration" json:"disappearing_duration"` // seconds
}

type Message struct {
	ID              primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	ConversationID  primitive.ObjectID  `bson:"conversation_id" json:"conversation_id"`
	SenderID        primitive.ObjectID  `bson:"sender_id" json:"sender_id"`
	Type            string              `bson:"type" json:"type"` // "text", "media", "thread_share", "system", "deleted"
	Content         string              `bson:"content" json:"content"`
	MediaFiles      []Media             `bson:"media_files" json:"media_files"`
	SharedThreadID  *primitive.ObjectID `bson:"shared_thread_id,omitempty" json:"shared_thread_id,omitempty"`
	ReplyToID       *primitive.ObjectID `bson:"reply_to_id,omitempty" json:"reply_to_id,omitempty"`
	ForwardedFromID *primitive.ObjectID `bson:"forwarded_from_id,omitempty" json:"forwarded_from_id,omitempty"`
	IsEdited        bool                `bson:"is_edited" json:"is_edited"`
	EditedAt        *time.Time          `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	IsDeleted       bool                `bson:"is_deleted" json:"is_deleted"`
	DeletedAt       *time.Time          `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	DeletedBy       *primitive.ObjectID `bson:"deleted_by,omitempty" json:"deleted_by,omitempty"`
	ReadBy          []MessageRead       `bson:"read_by" json:"read_by"`
	Reactions       []MessageReaction   `bson:"reactions" json:"reactions"`
	ExpiresAt       *time.Time          `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	Metadata        MessageMetadata     `bson:"metadata" json:"metadata"`
	CreatedAt       time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time           `bson:"updated_at" json:"updated_at"`

	// Populated fields
	Sender       *User      `bson:"-" json:"sender,omitempty"`
	ReplyTo      *Message   `bson:"-" json:"reply_to,omitempty"`
	SharedThread *Thread    `bson:"-" json:"shared_thread,omitempty"`
	IsRead       bool       `bson:"-" json:"is_read"`
	ReadAt       *time.Time `bson:"-" json:"read_at,omitempty"`
}

type MessageRead struct {
	UserID primitive.ObjectID `bson:"user_id" json:"user_id"`
	ReadAt time.Time          `bson:"read_at" json:"read_at"`
}

type MessageReaction struct {
	UserID  primitive.ObjectID `bson:"user_id" json:"user_id"`
	Emoji   string             `bson:"emoji" json:"emoji"`
	AddedAt time.Time          `bson:"added_at" json:"added_at"`
}

type MessageMetadata struct {
	Platform   string                 `bson:"platform" json:"platform"`
	DeviceInfo string                 `bson:"device_info" json:"device_info"`
	IPAddress  string                 `bson:"ip_address" json:"-"`
	UserAgent  string                 `bson:"user_agent" json:"-"`
	CustomData map[string]interface{} `bson:"custom_data,omitempty" json:"custom_data,omitempty"`
}

type ConversationParticipant struct {
	ID             primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	ConversationID primitive.ObjectID     `bson:"conversation_id" json:"conversation_id"`
	UserID         primitive.ObjectID     `bson:"user_id" json:"user_id"`
	Role           string                 `bson:"role" json:"role"` // "member", "admin", "owner"
	JoinedAt       time.Time              `bson:"joined_at" json:"joined_at"`
	LeftAt         *time.Time             `bson:"left_at,omitempty" json:"left_at,omitempty"`
	AddedBy        *primitive.ObjectID    `bson:"added_by,omitempty" json:"added_by,omitempty"`
	IsMuted        bool                   `bson:"is_muted" json:"is_muted"`
	MutedUntil     *time.Time             `bson:"muted_until,omitempty" json:"muted_until,omitempty"`
	LastReadAt     *time.Time             `bson:"last_read_at,omitempty" json:"last_read_at,omitempty"`
	UnreadCount    int64                  `bson:"unread_count" json:"unread_count"`
	Permissions    ParticipantPermissions `bson:"permissions" json:"permissions"`
}

type ParticipantPermissions struct {
	CanSendMessages  bool `bson:"can_send_messages" json:"can_send_messages"`
	CanSendMedia     bool `bson:"can_send_media" json:"can_send_media"`
	CanAddMembers    bool `bson:"can_add_members" json:"can_add_members"`
	CanRemoveMembers bool `bson:"can_remove_members" json:"can_remove_members"`
	CanEditInfo      bool `bson:"can_edit_info" json:"can_edit_info"`
}

type TypingIndicator struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ConversationID primitive.ObjectID `bson:"conversation_id" json:"conversation_id"`
	UserID         primitive.ObjectID `bson:"user_id" json:"user_id"`
	IsTyping       bool               `bson:"is_typing" json:"is_typing"`
	LastSeen       time.Time          `bson:"last_seen" json:"last_seen"`
	ExpiresAt      time.Time          `bson:"expires_at" json:"expires_at"`
}
