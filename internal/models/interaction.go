package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Like struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID   primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	LikedAt  time.Time          `bson:"liked_at" json:"liked_at"`
}

type Repost struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID           primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID         primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	OriginalThreadID primitive.ObjectID `bson:"original_thread_id" json:"original_thread_id"`
	Type             string             `bson:"type" json:"type"`       // "repost", "quote"
	Comment          string             `bson:"comment" json:"comment"` // for quote reposts
	RepostedAt       time.Time          `bson:"reposted_at" json:"reposted_at"`
}

type Bookmark struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID  `bson:"user_id" json:"user_id"`
	ThreadID  primitive.ObjectID  `bson:"thread_id" json:"thread_id"`
	FolderID  *primitive.ObjectID `bson:"folder_id,omitempty" json:"folder_id,omitempty"`
	Notes     string              `bson:"notes" json:"notes"`
	CreatedAt time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time           `bson:"updated_at" json:"updated_at"`
}

type BookmarkFolder struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Name        string             `bson:"name" json:"name" validate:"required,max=50"`
	Description string             `bson:"description" json:"description" validate:"max=200"`
	Color       string             `bson:"color" json:"color"`
	Icon        string             `bson:"icon" json:"icon"`
	IsPrivate   bool               `bson:"is_private" json:"is_private"`
	ItemsCount  int64              `bson:"items_count" json:"items_count"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

type Share struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID  primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	ShareType string             `bson:"share_type" json:"share_type"` // "copy_link", "dm", "external"
	Platform  string             `bson:"platform" json:"platform"`     // "twitter", "facebook", "instagram", etc.
	SharedAt  time.Time          `bson:"shared_at" json:"shared_at"`
}

type Report struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	ReporterID  primitive.ObjectID  `bson:"reporter_id" json:"reporter_id"`
	ThreadID    *primitive.ObjectID `bson:"thread_id,omitempty" json:"thread_id,omitempty"`
	UserID      *primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
	ReportType  string              `bson:"report_type" json:"report_type"` // "spam", "harassment", "hate_speech", "violence", "sexual_content", "misinformation", "copyright", "other"
	Category    string              `bson:"category" json:"category"`
	Description string              `bson:"description" json:"description"`
	Status      string              `bson:"status" json:"status"`     // "pending", "reviewing", "resolved", "dismissed"
	Priority    string              `bson:"priority" json:"priority"` // "low", "medium", "high", "urgent"
	Evidence    []ReportEvidence    `bson:"evidence" json:"evidence"`
	AdminNotes  string              `bson:"admin_notes" json:"admin_notes"`
	ReviewedBy  *primitive.ObjectID `bson:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time          `bson:"reviewed_at,omitempty" json:"reviewed_at,omitempty"`
	Resolution  string              `bson:"resolution" json:"resolution"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
}

type ReportEvidence struct {
	Type        string `bson:"type" json:"type"` // "screenshot", "url", "text"
	Content     string `bson:"content" json:"content"`
	Description string `bson:"description" json:"description"`
}

type UserList struct {
	ID             primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	OwnerID        primitive.ObjectID   `bson:"owner_id" json:"owner_id"`
	Name           string               `bson:"name" json:"name" validate:"required,max=50"`
	Description    string               `bson:"description" json:"description" validate:"max=200"`
	IsPrivate      bool                 `bson:"is_private" json:"is_private"`
	Members        []primitive.ObjectID `bson:"members" json:"members"`
	MembersCount   int64                `bson:"members_count" json:"members_count"`
	FollowersCount int64                `bson:"followers_count" json:"followers_count"`
	Avatar         string               `bson:"avatar" json:"avatar"`
	Banner         string               `bson:"banner" json:"banner"`
	CreatedAt      time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time            `bson:"updated_at" json:"updated_at"`
}

type ListMember struct {
	ID      primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ListID  primitive.ObjectID `bson:"list_id" json:"list_id"`
	UserID  primitive.ObjectID `bson:"user_id" json:"user_id"`
	AddedBy primitive.ObjectID `bson:"added_by" json:"added_by"`
	AddedAt time.Time          `bson:"added_at" json:"added_at"`
}

type ListFollower struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ListID     primitive.ObjectID `bson:"list_id" json:"list_id"`
	UserID     primitive.ObjectID `bson:"user_id" json:"user_id"`
	FollowedAt time.Time          `bson:"followed_at" json:"followed_at"`
}
