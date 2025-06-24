package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

type UploadHandler struct {
	storageService services.StorageService
}

func NewUploadHandler(storageService services.StorageService) *UploadHandler {
	return &UploadHandler{
		storageService: storageService,
	}
}

// UploadImage uploads an image file
func (h *UploadHandler) UploadImage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxImageSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Get optional metadata
	altText := c.PostForm("alt_text")
	quality := c.PostForm("quality")
	generateThumbnail := c.PostForm("generate_thumbnail") == "true"

	// Validate file size
	if header.Size > constants.MaxImageSize {
		utils.BadRequest(c, "Image file too large")
		return
	}

	// Validate file extension
	allowedExts := utils.GetImageExtensions()
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse quality
	imageQuality := constants.ImageQuality
	if quality != "" {
		if q, err := strconv.Atoi(quality); err == nil && q >= 1 && q <= 100 {
			imageQuality = q
		}
	}

	result, err := h.storageService.UploadImage(c.Request.Context(), &services.UploadImageRequest{
		File:              file,
		Filename:          header.Filename,
		Size:              header.Size,
		UserID:            userID.(primitive.ObjectID),
		AltText:           altText,
		Quality:           imageQuality,
		GenerateThumbnail: generateThumbnail,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload image")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Image uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Image uploaded successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

// UploadVideo uploads a video file
func (h *UploadHandler) UploadVideo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxVideoSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Get optional metadata
	altText := c.PostForm("alt_text")
	generateThumbnail := c.PostForm("generate_thumbnail") == "true"
	generatePreview := c.PostForm("generate_preview") == "true"

	// Validate file size
	if header.Size > constants.MaxVideoSize {
		utils.BadRequest(c, "Video file too large")
		return
	}

	// Validate file extension
	allowedExts := utils.GetVideoExtensions()
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	result, err := h.storageService.UploadVideo(c.Request.Context(), &services.UploadVideoRequest{
		File:              file,
		Filename:          header.Filename,
		Size:              header.Size,
		UserID:            userID.(primitive.ObjectID),
		AltText:           altText,
		GenerateThumbnail: generateThumbnail,
		GeneratePreview:   generatePreview,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload video")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Video uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Video uploaded successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

// UploadAudio uploads an audio file
func (h *UploadHandler) UploadAudio(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxAudioSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Get optional metadata
	title := c.PostForm("title")
	artist := c.PostForm("artist")

	// Validate file size
	if header.Size > constants.MaxAudioSize {
		utils.BadRequest(c, "Audio file too large")
		return
	}

	// Validate file extension
	allowedExts := utils.GetAudioExtensions()
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	result, err := h.storageService.UploadAudio(c.Request.Context(), &services.UploadAudioRequest{
		File:     file,
		Filename: header.Filename,
		Size:     header.Size,
		UserID:   userID.(primitive.ObjectID),
		Title:    title,
		Artist:   artist,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload audio")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Audio uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Audio uploaded successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

// UploadDocument uploads a document file
func (h *UploadHandler) UploadDocument(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxFileSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Get optional metadata
	description := c.PostForm("description")

	// Validate file size
	if header.Size > constants.MaxFileSize {
		utils.BadRequest(c, "Document file too large")
		return
	}

	// Validate file extension
	allowedExts := []string{"pdf", "doc", "docx", "txt", "md", "rtf", "odt"}
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	result, err := h.storageService.UploadDocument(c.Request.Context(), &services.UploadDocumentRequest{
		File:        file,
		Filename:    header.Filename,
		Size:        header.Size,
		UserID:      userID.(primitive.ObjectID),
		Description: description,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload document")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Document uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Document uploaded successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

// Avatar and cover specific uploads
func (h *UploadHandler) UploadAvatar(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxImageSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > constants.MaxImageSize {
		utils.BadRequest(c, "Avatar image too large")
		return
	}

	// Validate file extension
	allowedExts := utils.GetImageExtensions()
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	result, err := h.storageService.UploadAvatar(c.Request.Context(), &services.UploadAvatarRequest{
		File:     file,
		Filename: header.Filename,
		Size:     header.Size,
		UserID:   userID.(primitive.ObjectID),
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload avatar")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).Info("Avatar uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Avatar uploaded successfully", gin.H{
		"avatar_url": result.URL,
		"media":      result.Media,
	})
}

func (h *UploadHandler) UploadCover(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxImageSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > constants.MaxImageSize {
		utils.BadRequest(c, "Cover image too large")
		return
	}

	// Validate file extension
	allowedExts := utils.GetImageExtensions()
	if err := utils.ValidateFileExtension(header.Filename, allowedExts); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	result, err := h.storageService.UploadCover(c.Request.Context(), &services.UploadCoverRequest{
		File:     file,
		Filename: header.Filename,
		Size:     header.Size,
		UserID:   userID.(primitive.ObjectID),
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload cover")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).Info("Cover image uploaded successfully")

	utils.SuccessResponse(c, http.StatusCreated, "Cover image uploaded successfully", gin.H{
		"cover_url": result.URL,
		"media":     result.Media,
	})
}

// Chunked upload for large files
func (h *UploadHandler) InitChunkedUpload(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		Filename    string `json:"filename" binding:"required"`
		Size        int64  `json:"size" binding:"required"`
		ChunkSize   int64  `json:"chunk_size" binding:"required"`
		ContentType string `json:"content_type" binding:"required"`
		Checksum    string `json:"checksum"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	// Validate total file size
	if req.Size > constants.MaxFileSize {
		utils.BadRequest(c, "File too large")
		return
	}

	// Validate chunk size
	if req.ChunkSize > 50*1024*1024 { // Max 50MB per chunk
		utils.BadRequest(c, "Chunk size too large")
		return
	}

	session, err := h.storageService.InitChunkedUpload(c.Request.Context(), &services.InitChunkedUploadRequest{
		UserID:      userID.(primitive.ObjectID),
		Filename:    req.Filename,
		Size:        req.Size,
		ChunkSize:   req.ChunkSize,
		ContentType: req.ContentType,
		Checksum:    req.Checksum,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to initialize chunked upload")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Chunked upload initialized", gin.H{
		"upload_id":    session.ID,
		"total_chunks": session.TotalChunks,
		"chunk_size":   session.ChunkSize,
	})
}

func (h *UploadHandler) UploadChunk(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(50 * 1024 * 1024) // 50MB
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("chunk")
	if err != nil {
		utils.BadRequest(c, "No chunk provided")
		return
	}
	defer file.Close()

	uploadID := c.PostForm("upload_id")
	if uploadID == "" {
		utils.BadRequest(c, "Upload ID is required")
		return
	}

	chunkNumberStr := c.PostForm("chunk_number")
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		utils.BadRequest(c, "Invalid chunk number")
		return
	}

	chunkChecksum := c.PostForm("checksum")

	uploadObjID, err := primitive.ObjectIDFromHex(uploadID)
	if err != nil {
		utils.BadRequest(c, "Invalid upload ID")
		return
	}

	result, err := h.storageService.UploadChunk(c.Request.Context(), &services.UploadChunkRequest{
		UploadID:    uploadObjID,
		UserID:      userID.(primitive.ObjectID),
		ChunkNumber: chunkNumber,
		ChunkData:   file,
		ChunkSize:   header.Size,
		Checksum:    chunkChecksum,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload chunk")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Chunk uploaded successfully", gin.H{
		"chunk_number":    chunkNumber,
		"uploaded_chunks": result.UploadedChunks,
		"total_chunks":    result.TotalChunks,
		"upload_complete": result.IsComplete,
	})
}

func (h *UploadHandler) CompleteChunkedUpload(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		UploadID string `json:"upload_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Upload ID is required")
		return
	}

	uploadObjID, err := primitive.ObjectIDFromHex(req.UploadID)
	if err != nil {
		utils.BadRequest(c, "Invalid upload ID")
		return
	}

	result, err := h.storageService.CompleteChunkedUpload(c.Request.Context(), uploadObjID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to complete chunked upload")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Chunked upload completed")

	utils.SuccessResponse(c, http.StatusOK, "Upload completed successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

func (h *UploadHandler) CancelChunkedUpload(c *gin.Context) {
	uploadIDStr := c.Param("upload_id")
	uploadID, err := primitive.ObjectIDFromHex(uploadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid upload ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.storageService.CancelChunkedUpload(c.Request.Context(), uploadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to cancel upload")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Upload cancelled successfully", nil)
}

// Temporary uploads for drafts
func (h *UploadHandler) UploadTemporary(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(constants.MaxFileSize)
	if err != nil {
		utils.BadRequest(c, "Failed to parse form data")
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file provided")
		return
	}
	defer file.Close()

	// Get file type
	fileType := c.PostForm("type")
	if fileType == "" {
		// Auto-detect from extension
		ext := strings.ToLower(strings.TrimPrefix(strings.ToLower(header.Filename), "."))
		if contains(utils.GetImageExtensions(), ext) {
			fileType = "image"
		} else if contains(utils.GetVideoExtensions(), ext) {
			fileType = "video"
		} else if contains(utils.GetAudioExtensions(), ext) {
			fileType = "audio"
		} else {
			fileType = "document"
		}
	}

	// Validate file size based on type
	var maxSize int64
	switch fileType {
	case "image":
		maxSize = constants.MaxImageSize
	case "video":
		maxSize = constants.MaxVideoSize
	case "audio":
		maxSize = constants.MaxAudioSize
	default:
		maxSize = constants.MaxFileSize
	}

	if header.Size > maxSize {
		utils.BadRequest(c, "File too large for type "+fileType)
		return
	}

	result, err := h.storageService.UploadTemporary(c.Request.Context(), &services.UploadTemporaryRequest{
		File:     file,
		Filename: header.Filename,
		Size:     header.Size,
		Type:     fileType,
		UserID:   userID.(primitive.ObjectID),
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to upload temporary file")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("temp_id", result.TempID).Info("Temporary file uploaded")

	utils.SuccessResponse(c, http.StatusCreated, "Temporary file uploaded successfully", gin.H{
		"temp_id":    result.TempID,
		"temp_url":   result.TempURL,
		"expires_at": result.ExpiresAt,
	})
}

func (h *UploadHandler) MakePermanent(c *gin.Context) {
	tempIDStr := c.Param("temp_id")
	tempID, err := primitive.ObjectIDFromHex(tempIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid temporary ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var req struct {
		AltText string `json:"alt_text"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Alt text is optional
	}

	result, err := h.storageService.MakePermanent(c.Request.Context(), tempID, userID.(primitive.ObjectID), req.AltText)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to make file permanent")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", result.Media.ID).Info("Temporary file made permanent")

	utils.SuccessResponse(c, http.StatusOK, "File made permanent successfully", gin.H{
		"media": result.Media,
		"url":   result.URL,
	})
}

// File management
func (h *UploadHandler) GetUploadHistory(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	fileType := c.Query("type")

	result, err := h.storageService.GetUploadHistory(c.Request.Context(), userID.(primitive.ObjectID), fileType, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get upload history")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Upload history retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *UploadHandler) DeleteFile(c *gin.Context) {
	fileIDStr := c.Param("file_id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid file ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.storageService.DeleteFile(c.Request.Context(), fileID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete file")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("file_id", fileID).Info("File deleted")

	utils.SuccessResponse(c, http.StatusOK, "File deleted successfully", nil)
}

func (h *UploadHandler) GetFileInfo(c *gin.Context) {
	fileIDStr := c.Param("file_id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid file ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	fileInfo, err := h.storageService.GetFileInfo(c.Request.Context(), fileID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "File not found")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "File info retrieved", gin.H{
		"file": fileInfo,
	})
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
