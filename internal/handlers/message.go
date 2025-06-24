package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"thread-app-backend/internal/models"
	"thread-app-backend/internal/services"
	"thread-app-backend/internal/utils"
	"thread-app-backend/pkg/constants"
	"thread-app-backend/pkg/errors"
	"thread-app-backend/pkg/logger"
)

type MessageHandler struct {
	messageService   services.MessageService
	webSocketService services.WebSocketService
}

func NewMessageHandler(messageService services.MessageService, webSocketService services.WebSocketService) *MessageHandler {
	return &MessageHandler{
		messageService:   messageService,
		webSocketService: webSocketService,
	}
}

// GetConversations returns user's conversations
func (h *MessageHandler) GetConversations(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.messageService.GetConversations(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get conversations")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Conversations retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// CreateConversation creates a new conversation
func (h *MessageHandler) CreateConversation(c *gin.Context) {
	var req struct {
		Type         string   `json:"type" binding:"required,oneof=direct group"`
		Participants []string `json:"participants" binding:"required,min=1"`
		Title        string   `json:"title" binding:"max=50"`
		Description  string   `json:"description" binding:"max=200"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Validate participant count
	if req.Type == "direct" && len(req.Participants) != 1 {
		utils.BadRequest(c, "Direct conversation must have exactly 1 other participant")
		return
	}

	if req.Type == "group" && len(req.Participants) > constants.MaxConversationParticipants-1 {
		utils.BadRequest(c, "Too many participants")
		return
	}

	// Convert participant usernames to IDs
	participantIDs := make([]primitive.ObjectID, len(req.Participants))
	for i, username := range req.Participants {
		user, err := h.messageService.GetUserByUsername(c.Request.Context(), username)
		if err != nil {
			utils.BadRequest(c, "Invalid participant: "+username)
			return
		}
		participantIDs[i] = user.ID
	}

	// Add current user to participants
	allParticipants := append([]primitive.ObjectID{userID.(primitive.ObjectID)}, participantIDs...)

	conversation, err := h.messageService.CreateConversation(c.Request.Context(), &services.CreateConversationRequest{
		Type:         req.Type,
		CreatorID:    userID.(primitive.ObjectID),
		Participants: allParticipants,
		Title:        req.Title,
		Description:  req.Description,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to create conversation")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("conversation_id", conversation.ID).Info("Conversation created")

	utils.SuccessResponse(c, http.StatusCreated, "Conversation created successfully", gin.H{
		"conversation": conversation,
	})
}

// GetConversation returns a specific conversation
func (h *MessageHandler) GetConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	conversation, err := h.messageService.GetConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Conversation not found")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Conversation retrieved", gin.H{
		"conversation": conversation,
	})
}

// UpdateConversation updates conversation details
func (h *MessageHandler) UpdateConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		Title       string `json:"title" binding:"max=50"`
		Description string `json:"description" binding:"max=200"`
		Avatar      string `json:"avatar" binding:"url_optional"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	conversation, err := h.messageService.UpdateConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID), &services.UpdateConversationRequest{
		Title:       req.Title,
		Description: req.Description,
		Avatar:      req.Avatar,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Conversation updated successfully", gin.H{
		"conversation": conversation,
	})
}

// DeleteConversation deletes a conversation
func (h *MessageHandler) DeleteConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.DeleteConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Conversation deleted successfully", nil)
}

// LeaveConversation removes user from conversation
func (h *MessageHandler) LeaveConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.LeaveConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to leave conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Left conversation successfully", nil)
}

// JoinConversation adds user to conversation
func (h *MessageHandler) JoinConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.JoinConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to join conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Joined conversation successfully", nil)
}

// GetMessages returns messages in a conversation
func (h *MessageHandler) GetMessages(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.messageService.GetMessages(c.Request.Context(), conversationID, userID.(primitive.ObjectID), params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get messages")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Messages retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// SendMessage sends a message in a conversation
func (h *MessageHandler) SendMessage(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		Type           string         `json:"type" binding:"required,message_type"`
		Content        string         `json:"content" binding:"max=2000"`
		MediaFiles     []models.Media `json:"media_files"`
		SharedThreadID *string        `json:"shared_thread_id"`
		ReplyToID      *string        `json:"reply_to_id"`
		ExpiresIn      *int64         `json:"expires_in"` // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Validate content based on type
	if req.Type == "text" && req.Content == "" {
		utils.BadRequest(c, "Text messages require content")
		return
	}

	if req.Type == "media" && len(req.MediaFiles) == 0 {
		utils.BadRequest(c, "Media messages require media files")
		return
	}

	if req.Type == "thread_share" && req.SharedThreadID == nil {
		utils.BadRequest(c, "Thread share messages require shared_thread_id")
		return
	}

	// Validate content length
	if len(req.Content) > constants.MaxMessageContentLength {
		utils.BadRequest(c, "Message content too long")
		return
	}

	// Validate media files count
	if len(req.MediaFiles) > constants.MaxMessageMediaFiles {
		utils.BadRequest(c, "Too many media files")
		return
	}

	// Convert string IDs to ObjectIDs
	var sharedThreadID, replyToID *primitive.ObjectID
	if req.SharedThreadID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.SharedThreadID); err == nil {
			sharedThreadID = &id
		} else {
			utils.BadRequest(c, "Invalid shared thread ID")
			return
		}
	}
	if req.ReplyToID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.ReplyToID); err == nil {
			replyToID = &id
		} else {
			utils.BadRequest(c, "Invalid reply to message ID")
			return
		}
	}

	// Calculate expiry time
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	message, err := h.messageService.SendMessage(c.Request.Context(), &services.SendMessageRequest{
		ConversationID: conversationID,
		SenderID:       userID.(primitive.ObjectID),
		Type:           req.Type,
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		SharedThreadID: sharedThreadID,
		ReplyToID:      replyToID,
		ExpiresAt:      expiresAt,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to send message")
		}
		return
	}

	// Send real-time message to conversation participants
	go h.webSocketService.BroadcastMessageToConversation(conversationID, message)

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("conversation_id", conversationID).WithField("message_id", message.ID).Info("Message sent")

	utils.SuccessResponse(c, http.StatusCreated, "Message sent successfully", gin.H{
		"message": message,
	})
}

// UpdateMessage updates a message
func (h *MessageHandler) UpdateMessage(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	messageIDStr := c.Param("message_id")
	messageID, err := primitive.ObjectIDFromHex(messageIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid message ID")
		return
	}

	var req struct {
		Content string `json:"content" binding:"required,max=2000"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	message, err := h.messageService.UpdateMessage(c.Request.Context(), messageID, userID.(primitive.ObjectID), req.Content)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update message")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastMessageUpdate(conversationID, message, "updated")

	utils.SuccessResponse(c, http.StatusOK, "Message updated successfully", gin.H{
		"message": message,
	})
}

// DeleteMessage deletes a message
func (h *MessageHandler) DeleteMessage(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	messageIDStr := c.Param("message_id")
	messageID, err := primitive.ObjectIDFromHex(messageIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid message ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.DeleteMessage(c.Request.Context(), messageID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete message")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastMessageUpdate(conversationID, &models.Message{ID: messageID}, "deleted")

	utils.SuccessResponse(c, http.StatusOK, "Message deleted successfully", nil)
}

// ReactToMessage adds a reaction to a message
func (h *MessageHandler) ReactToMessage(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	messageIDStr := c.Param("message_id")
	messageID, err := primitive.ObjectIDFromHex(messageIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid message ID")
		return
	}

	var req struct {
		Emoji string `json:"emoji" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Emoji is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	message, err := h.messageService.ReactToMessage(c.Request.Context(), messageID, userID.(primitive.ObjectID), req.Emoji)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to react to message")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastMessageUpdate(conversationID, message, "reacted")

	utils.SuccessResponse(c, http.StatusOK, "Reaction added successfully", gin.H{
		"message": message,
	})
}

// RemoveReaction removes a reaction from a message
func (h *MessageHandler) RemoveReaction(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	messageIDStr := c.Param("message_id")
	messageID, err := primitive.ObjectIDFromHex(messageIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid message ID")
		return
	}

	var req struct {
		Emoji string `json:"emoji" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Emoji is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	message, err := h.messageService.RemoveReaction(c.Request.Context(), messageID, userID.(primitive.ObjectID), req.Emoji)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to remove reaction")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastMessageUpdate(conversationID, message, "reaction_removed")

	utils.SuccessResponse(c, http.StatusOK, "Reaction removed successfully", gin.H{
		"message": message,
	})
}

// ForwardMessage forwards a message to another conversation
func (h *MessageHandler) ForwardMessage(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	_, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	messageIDStr := c.Param("message_id")
	messageID, err := primitive.ObjectIDFromHex(messageIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid message ID")
		return
	}

	var req struct {
		TargetConversationIDs []string `json:"target_conversation_ids" binding:"required,min=1"`
		Comment               string   `json:"comment" binding:"max=500"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Convert target conversation IDs
	targetIDs := make([]primitive.ObjectID, len(req.TargetConversationIDs))
	for i, idStr := range req.TargetConversationIDs {
		if id, err := primitive.ObjectIDFromHex(idStr); err == nil {
			targetIDs[i] = id
		} else {
			utils.BadRequest(c, "Invalid target conversation ID: "+idStr)
			return
		}
	}

	forwardedMessages, err := h.messageService.ForwardMessage(c.Request.Context(), messageID, userID.(primitive.ObjectID), targetIDs, req.Comment)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to forward message")
		}
		return
	}

	// Send real-time messages to target conversations
	for _, msg := range forwardedMessages {
		go h.webSocketService.BroadcastMessageToConversation(msg.ConversationID, msg)
	}

	utils.SuccessResponse(c, http.StatusOK, "Message forwarded successfully", gin.H{
		"forwarded_to": len(forwardedMessages),
		"messages":     forwardedMessages,
	})
}

// MarkAsRead marks messages as read
func (h *MessageHandler) MarkAsRead(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		MessageID *string `json:"message_id"` // If provided, mark up to this message, otherwise mark all
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// message_id is optional
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var messageID *primitive.ObjectID
	if req.MessageID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.MessageID); err == nil {
			messageID = &id
		} else {
			utils.BadRequest(c, "Invalid message ID")
			return
		}
	}

	err = h.messageService.MarkAsRead(c.Request.Context(), conversationID, userID.(primitive.ObjectID), messageID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to mark messages as read")
		}
		return
	}

	// Send real-time read receipt to conversation participants
	go h.webSocketService.BroadcastReadReceipt(conversationID, userID.(primitive.ObjectID), messageID)

	utils.SuccessResponse(c, http.StatusOK, "Messages marked as read", nil)
}

// SendTypingIndicator sends typing indicator
func (h *MessageHandler) SendTypingIndicator(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		IsTyping bool `json:"is_typing"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "is_typing is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.UpdateTypingIndicator(c.Request.Context(), conversationID, userID.(primitive.ObjectID), req.IsTyping)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update typing indicator")
		}
		return
	}

	// Send real-time typing indicator to conversation participants
	go h.webSocketService.BroadcastTypingIndicator(conversationID, userID.(primitive.ObjectID), req.IsTyping)

	utils.SuccessResponse(c, http.StatusOK, "Typing indicator updated", nil)
}

// GetParticipants returns conversation participants
func (h *MessageHandler) GetParticipants(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.messageService.GetParticipants(c.Request.Context(), conversationID, userID.(primitive.ObjectID), params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get participants")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Participants retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// AddParticipant adds a participant to the conversation
func (h *MessageHandler) AddParticipant(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Get user to add
	userToAdd, err := h.messageService.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		utils.BadRequest(c, "Invalid username")
		return
	}

	err = h.messageService.AddParticipant(c.Request.Context(), conversationID, userID.(primitive.ObjectID), userToAdd.ID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to add participant")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastConversationUpdate(conversationID, "participant_added", userToAdd.ID)

	utils.SuccessResponse(c, http.StatusOK, "Participant added successfully", nil)
}

// RemoveParticipant removes a participant from the conversation
func (h *MessageHandler) RemoveParticipant(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	participantIDStr := c.Param("user_id")
	participantID, err := primitive.ObjectIDFromHex(participantIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid participant ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.RemoveParticipant(c.Request.Context(), conversationID, userID.(primitive.ObjectID), participantID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to remove participant")
		}
		return
	}

	// Send real-time update to conversation participants
	go h.webSocketService.BroadcastConversationUpdate(conversationID, "participant_removed", participantID)

	utils.SuccessResponse(c, http.StatusOK, "Participant removed successfully", nil)
}

// UpdateParticipantRole updates a participant's role
func (h *MessageHandler) UpdateParticipantRole(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	participantIDStr := c.Param("user_id")
	participantID, err := primitive.ObjectIDFromHex(participantIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid participant ID")
		return
	}

	var req struct {
		Role string `json:"role" binding:"required,oneof=member admin"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid role is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.UpdateParticipantRole(c.Request.Context(), conversationID, userID.(primitive.ObjectID), participantID, req.Role)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update participant role")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Participant role updated successfully", nil)
}

// MuteConversation mutes a conversation for the user
func (h *MessageHandler) MuteConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	var req struct {
		Duration *int64 `json:"duration"` // Duration in seconds, nil for indefinite
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Duration is optional
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var mutedUntil *time.Time
	if req.Duration != nil {
		until := time.Now().Add(time.Duration(*req.Duration) * time.Second)
		mutedUntil = &until
	}

	err = h.messageService.MuteConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID), mutedUntil)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to mute conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Conversation muted successfully", nil)
}

// UnmuteConversation unmutes a conversation for the user
func (h *MessageHandler) UnmuteConversation(c *gin.Context) {
	conversationIDStr := c.Param("conversation_id")
	conversationID, err := primitive.ObjectIDFromHex(conversationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid conversation ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.UnmuteConversation(c.Request.Context(), conversationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unmute conversation")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Conversation unmuted successfully", nil)
}

// Direct message shortcuts
func (h *MessageHandler) GetDirectMessages(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.messageService.GetDirectMessages(c.Request.Context(), userID.(primitive.ObjectID), username, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get direct messages")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Direct messages retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *MessageHandler) SendDirectMessage(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	var req struct {
		Content string `json:"content" binding:"required,max=2000"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	message, err := h.messageService.SendDirectMessage(c.Request.Context(), userID.(primitive.ObjectID), username, req.Content)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to send direct message")
		}
		return
	}

	// Send real-time message
	go h.webSocketService.BroadcastMessageToConversation(message.ConversationID, message)

	utils.SuccessResponse(c, http.StatusCreated, "Direct message sent successfully", gin.H{
		"message": message,
	})
}

// SearchMessages searches for messages
func (h *MessageHandler) SearchMessages(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.BadRequest(c, "Search query is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	conversationID := c.Query("conversation_id")

	var convID *primitive.ObjectID
	if conversationID != "" {
		if id, err := primitive.ObjectIDFromHex(conversationID); err == nil {
			convID = &id
		} else {
			utils.BadRequest(c, "Invalid conversation ID")
			return
		}
	}

	result, err := h.messageService.SearchMessages(c.Request.Context(), userID.(primitive.ObjectID), query, convID, params)
	if err != nil {
		utils.InternalServerError(c, "Search failed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Search results", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// Message requests
func (h *MessageHandler) GetMessageRequests(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.messageService.GetMessageRequests(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get message requests")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Message requests retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *MessageHandler) AcceptMessageRequest(c *gin.Context) {
	requestIDStr := c.Param("request_id")
	requestID, err := primitive.ObjectIDFromHex(requestIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid request ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.AcceptMessageRequest(c.Request.Context(), requestID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to accept message request")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Message request accepted", nil)
}

func (h *MessageHandler) DeclineMessageRequest(c *gin.Context) {
	requestIDStr := c.Param("request_id")
	requestID, err := primitive.ObjectIDFromHex(requestIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid request ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.messageService.DeclineMessageRequest(c.Request.Context(), requestID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to decline message request")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Message request declined", nil)
}
