package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Thread struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	AuthorID         primitive.ObjectID   `bson:"author_id" json:"author_id"`
	Content          string               `bson:"content" json:"content" validate:"max=500"`
	MediaFiles       []Media              `bson:"media_files" json:"media_files"`
	Type             string               `bson:"type" json:"type"` // "thread", "reply", "repost", "quote"
	ParentID         *primitive.ObjectID  `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
	OriginalThreadID *primitive.ObjectID  `bson:"original_thread_id,omitempty" json:"original_thread_id,omitempty"`
	QuotedThreadID   *primitive.ObjectID  `bson:"quoted_thread_id,omitempty" json:"quoted_thread_id,omitempty"`
	ThreadChainID    *primitive.ObjectID  `bson:"thread_chain_id,omitempty" json:"thread_chain_id,omitempty"`
	Hashtags         []string             `bson:"hashtags" json:"hashtags"`
	Mentions         []primitive.ObjectID `bson:"mentions" json:"mentions"`
	IsEdited         bool                 `bson:"is_edited" json:"is_edited"`
	EditedAt         *time.Time           `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	EditHistory      []EditHistory        `bson:"edit_history" json:"edit_history"`
	IsPinned         bool                 `bson:"is_pinned" json:"is_pinned"`
	IsArchived       bool                 `bson:"is_archived" json:"is_archived"`
	IsDeleted        bool                 `bson:"is_deleted" json:"is_deleted"`
	DeletedAt        *time.Time           `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	Visibility       string               `bson:"visibility" json:"visibility"`         // "public", "followers", "mentioned", "circle"
	ReplySettings    string               `bson:"reply_settings" json:"reply_settings"` // "everyone", "following", "mentioned", "none"
	Location         *Location            `bson:"location,omitempty" json:"location,omitempty"`
	Poll             *Poll                `bson:"poll,omitempty" json:"poll,omitempty"`
	ScheduledAt      *time.Time           `bson:"scheduled_at,omitempty" json:"scheduled_at,omitempty"`
	IsScheduled      bool                 `bson:"is_scheduled" json:"is_scheduled"`
	Language         string               `bson:"language" json:"language"`
	ContentWarning   string               `bson:"content_warning" json:"content_warning"`
	IsSensitive      bool                 `bson:"is_sensitive" json:"is_sensitive"`
	CreatedAt        time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time            `bson:"updated_at" json:"updated_at"`

	// Engagement metrics
	LikesCount     int64 `bson:"likes_count" json:"likes_count"`
	RepostsCount   int64 `bson:"reposts_count" json:"reposts_count"`
	RepliesCount   int64 `bson:"replies_count" json:"replies_count"`
	QuotesCount    int64 `bson:"quotes_count" json:"quotes_count"`
	ViewsCount     int64 `bson:"views_count" json:"views_count"`
	SharesCount    int64 `bson:"shares_count" json:"shares_count"`
	BookmarksCount int64 `bson:"bookmarks_count" json:"bookmarks_count"`

	// Populated fields (not stored in DB)
	Author       *User    `bson:"-" json:"author,omitempty"`
	ParentThread *Thread  `bson:"-" json:"parent_thread,omitempty"`
	QuotedThread *Thread  `bson:"-" json:"quoted_thread,omitempty"`
	Replies      []Thread `bson:"-" json:"replies,omitempty"`
	IsLiked      bool     `bson:"-" json:"is_liked"`
	IsReposted   bool     `bson:"-" json:"is_reposted"`
	IsBookmarked bool     `bson:"-" json:"is_bookmarked"`
	CanReply     bool     `bson:"-" json:"can_reply"`
	CanRepost    bool     `bson:"-" json:"can_repost"`
}

type Media struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Type         string             `bson:"type" json:"type"` // "image", "video", "gif", "audio"
	URL          string             `bson:"url" json:"url"`
	ThumbnailURL string             `bson:"thumbnail_url" json:"thumbnail_url"`
	PreviewURL   string             `bson:"preview_url" json:"preview_url"`
	Width        int                `bson:"width" json:"width"`
	Height       int                `bson:"height" json:"height"`
	Size         int64              `bson:"size" json:"size"`
	Duration     *float64           `bson:"duration,omitempty" json:"duration,omitempty"` // for videos/audio
	AltText      string             `bson:"alt_text" json:"alt_text"`
	BlurHash     string             `bson:"blur_hash" json:"blur_hash"`
	Metadata     MediaMetadata      `bson:"metadata" json:"metadata"`
}

type MediaMetadata struct {
	OriginalName string                 `bson:"original_name" json:"original_name"`
	MimeType     string                 `bson:"mime_type" json:"mime_type"`
	Checksum     string                 `bson:"checksum" json:"checksum"`
	ExifData     map[string]interface{} `bson:"exif_data,omitempty" json:"exif_data,omitempty"`
	ProcessedAt  time.Time              `bson:"processed_at" json:"processed_at"`
}

type Location struct {
	Name        string  `bson:"name" json:"name"`
	Latitude    float64 `bson:"latitude" json:"latitude"`
	Longitude   float64 `bson:"longitude" json:"longitude"`
	Address     string  `bson:"address" json:"address"`
	City        string  `bson:"city" json:"city"`
	Country     string  `bson:"country" json:"country"`
	CountryCode string  `bson:"country_code" json:"country_code"`
}

type Poll struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Question      string             `bson:"question" json:"question"`
	Options       []PollOption       `bson:"options" json:"options"`
	ExpiresAt     time.Time          `bson:"expires_at" json:"expires_at"`
	IsExpired     bool               `bson:"is_expired" json:"is_expired"`
	TotalVotes    int64              `bson:"total_votes" json:"total_votes"`
	AllowMultiple bool               `bson:"allow_multiple" json:"allow_multiple"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
}

type PollOption struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Text       string             `bson:"text" json:"text"`
	VotesCount int64              `bson:"votes_count" json:"votes_count"`
	Percentage float64            `bson:"-" json:"percentage"`
	IsVoted    bool               `bson:"-" json:"is_voted"`
}

type PollVote struct {
	ID       primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	PollID   primitive.ObjectID   `bson:"poll_id" json:"poll_id"`
	UserID   primitive.ObjectID   `bson:"user_id" json:"user_id"`
	ThreadID primitive.ObjectID   `bson:"thread_id" json:"thread_id"`
	Options  []primitive.ObjectID `bson:"options" json:"options"`
	VotedAt  time.Time            `bson:"voted_at" json:"voted_at"`
}

type EditHistory struct {
	Content    string    `bson:"content" json:"content"`
	MediaFiles []Media   `bson:"media_files" json:"media_files"`
	EditedAt   time.Time `bson:"edited_at" json:"edited_at"`
	EditReason string    `bson:"edit_reason" json:"edit_reason"`
}

type ThreadView struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ThreadID primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	UserID   primitive.ObjectID `bson:"user_id" json:"user_id"`
	ViewedAt time.Time          `bson:"viewed_at" json:"viewed_at"`
	Duration int64              `bson:"duration" json:"duration"` // milliseconds
	Source   string             `bson:"source" json:"source"`     // "timeline", "profile", "search", "direct"
}
