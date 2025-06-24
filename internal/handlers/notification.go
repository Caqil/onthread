package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

type NotificationHandler struct {
	notificationService services.NotificationService
}

func NewNotificationHandler(notificationService services.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
	}
}

// GetNotifications returns user's notifications
func (h *NotificationHandler) GetNotifications(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	notificationType := c.Query("type")
	onlyUnread := c.Query("unread") == "true"

	result, err := h.notificationService.GetNotifications(c.Request.Context(), &services.GetNotificationsRequest{
		UserID:           userID.(primitive.ObjectID),
		Type:             notificationType,
		OnlyUnread:       onlyUnread,
		PaginationParams: params,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to get notifications")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Notifications retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
		Total:      result.TotalCount,
	})
}

// GetUnreadNotifications returns user's unread notifications
func (h *NotificationHandler) GetUnreadNotifications(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	params.Limit = 50 // Limit unread notifications to 50

	result, err := h.notificationService.GetNotifications(c.Request.Context(), &services.GetNotificationsRequest{
		UserID:           userID.(primitive.ObjectID),
		OnlyUnread:       true,
		PaginationParams: params,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to get unread notifications")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Unread notifications retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
		Total:      result.TotalCount,
	})
}

// GetNotificationCount returns notification counts
func (h *NotificationHandler) GetNotificationCount(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	counts, err := h.notificationService.GetNotificationCounts(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get notification counts")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notification counts retrieved", gin.H{
		"counts": counts,
	})
}

// MarkAsRead marks a notification as read
func (h *NotificationHandler) MarkAsRead(c *gin.Context) {
	notificationIDStr := c.Param("notification_id")
	notificationID, err := primitive.ObjectIDFromHex(notificationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid notification ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.notificationService.MarkAsRead(c.Request.Context(), notificationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to mark notification as read")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notification marked as read", nil)
}

// MarkAllAsRead marks all notifications as read
func (h *NotificationHandler) MarkAllAsRead(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Type   string `json:"type"`   // Optional: mark specific type as read
		Before string `json:"before"` // Optional: mark all before this date as read
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Both fields are optional
	}

	var beforeID *primitive.ObjectID
	if req.Before != "" {
		if id, err := primitive.ObjectIDFromHex(req.Before); err == nil {
			beforeID = &id
		} else {
			utils.BadRequest(c, "Invalid before notification ID")
			return
		}
	}

	count, err := h.notificationService.MarkAllAsRead(c.Request.Context(), userID.(primitive.ObjectID), req.Type, beforeID)
	if err != nil {
		utils.InternalServerError(c, "Failed to mark notifications as read")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notifications marked as read", gin.H{
		"marked_count": count,
	})
}

// DeleteNotification deletes a notification
func (h *NotificationHandler) DeleteNotification(c *gin.Context) {
	notificationIDStr := c.Param("notification_id")
	notificationID, err := primitive.ObjectIDFromHex(notificationIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid notification ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.notificationService.DeleteNotification(c.Request.Context(), notificationID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete notification")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notification deleted successfully", nil)
}

// ClearAllNotifications clears all notifications
func (h *NotificationHandler) ClearAllNotifications(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Type      string `json:"type"`       // Optional: clear specific type
		OlderThan string `json:"older_than"` // Optional: clear notifications older than this
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Both fields are optional
	}

	count, err := h.notificationService.ClearAllNotifications(c.Request.Context(), userID.(primitive.ObjectID), req.Type, req.OlderThan)
	if err != nil {
		utils.InternalServerError(c, "Failed to clear notifications")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notifications cleared successfully", gin.H{
		"cleared_count": count,
	})
}

// GetNotificationSettings returns user's notification settings
func (h *NotificationHandler) GetNotificationSettings(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	settings, err := h.notificationService.GetNotificationSettings(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get notification settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Notification settings retrieved", gin.H{
		"settings": settings,
	})
}

// UpdateNotificationSettings updates user's notification settings
func (h *NotificationHandler) UpdateNotificationSettings(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req models.NotificationSettings

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	// Set user ID
	req.UserID = userID.(primitive.ObjectID)

	settings, err := h.notificationService.UpdateNotificationSettings(c.Request.Context(), &req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update notification settings")
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).Info("Notification settings updated")

	utils.SuccessResponse(c, http.StatusOK, "Notification settings updated successfully", gin.H{
		"settings": settings,
	})
}

// GetDevices returns user's registered devices
func (h *NotificationHandler) GetDevices(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	devices, err := h.notificationService.GetDevices(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get devices")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Devices retrieved", gin.H{
		"devices": devices,
	})
}

// RegisterDevice registers a device for push notifications
func (h *NotificationHandler) RegisterDevice(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Token      string `json:"token" binding:"required"`
		Platform   string `json:"platform" binding:"required,oneof=ios android web"`
		DeviceName string `json:"device_name" binding:"max=100"`
		AppVersion string `json:"app_version" binding:"max=20"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	device, err := h.notificationService.RegisterDevice(c.Request.Context(), &services.RegisterDeviceRequest{
		UserID:     userID.(primitive.ObjectID),
		Token:      req.Token,
		Platform:   req.Platform,
		DeviceName: req.DeviceName,
		AppVersion: req.AppVersion,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to register device")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("platform", req.Platform).Info("Device registered for notifications")

	utils.SuccessResponse(c, http.StatusCreated, "Device registered successfully", gin.H{
		"device": device,
	})
}

// UnregisterDevice removes a device from push notifications
func (h *NotificationHandler) UnregisterDevice(c *gin.Context) {
	deviceIDStr := c.Param("device_id")
	deviceID, err := primitive.ObjectIDFromHex(deviceIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid device ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.notificationService.UnregisterDevice(c.Request.Context(), deviceID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unregister device")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Device unregistered successfully", nil)
}

// TestNotification sends a test notification
func (h *NotificationHandler) TestNotification(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Type    string `json:"type" binding:"required,oneof=push email in_app"`
		Title   string `json:"title" binding:"required,max=100"`
		Content string `json:"content" binding:"required,max=500"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	err := h.notificationService.SendTestNotification(c.Request.Context(), &services.TestNotificationRequest{
		UserID:  userID.(primitive.ObjectID),
		Type:    req.Type,
		Title:   req.Title,
		Content: req.Content,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to send test notification")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Test notification sent successfully", nil)
}

// GetSubscriptions returns user's notification subscriptions
func (h *NotificationHandler) GetSubscriptions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.notificationService.GetSubscriptions(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get subscriptions")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Subscriptions retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// SubscribeToThread subscribes to notifications for a thread
func (h *NotificationHandler) SubscribeToThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Types []string `json:"types"` // Optional: specific notification types to subscribe to
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Types is optional
	}

	err = h.notificationService.SubscribeToThread(c.Request.Context(), userID.(primitive.ObjectID), threadID, req.Types)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to subscribe to thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Subscribed to thread notifications", nil)
}

// UnsubscribeFromThread unsubscribes from notifications for a thread
func (h *NotificationHandler) UnsubscribeFromThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.notificationService.UnsubscribeFromThread(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unsubscribe from thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Unsubscribed from thread notifications", nil)
}

// SubscribeToUser subscribes to notifications for a user
func (h *NotificationHandler) SubscribeToUser(c *gin.Context) {
	targetUserIDStr := c.Param("user_id")
	targetUserID, err := primitive.ObjectIDFromHex(targetUserIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Types []string `json:"types"` // Optional: specific notification types to subscribe to
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Types is optional
	}

	err = h.notificationService.SubscribeToUser(c.Request.Context(), userID.(primitive.ObjectID), targetUserID, req.Types)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to subscribe to user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Subscribed to user notifications", nil)
}

// UnsubscribeFromUser unsubscribes from notifications for a user
func (h *NotificationHandler) UnsubscribeFromUser(c *gin.Context) {
	targetUserIDStr := c.Param("user_id")
	targetUserID, err := primitive.ObjectIDFromHex(targetUserIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.notificationService.UnsubscribeFromUser(c.Request.Context(), userID.(primitive.ObjectID), targetUserID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unsubscribe from user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Unsubscribed from user notifications", nil)
}
