package head_doc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type FileGeter interface {
	GetFile(id, token string) (string, error)
}

type ErrorData struct {
	Error Error `json:"error"`
}

type Error struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

var FileCache sync.Map

const (
	defaultContentType = "application/octet-stream"
	maxMetadataLength  = 10
)

var (
	ErrMissingID    = errors.New("id is required")
	ErrMissingToken = errors.New("token is required")
	ErrDiskError    = errors.New("error serving file from disk")
)

func GetDocHead(log *slog.Logger, flGeter FileGeter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.file.get.GetDochead"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", r.URL.Path),
		)

		id := chi.URLParam(r, "id")
		token := r.URL.Query().Get("token")

		if id == "" {
			respondWithError(w, r, log, http.StatusBadRequest, ErrMissingID.Error())
			return
		}

		if token == "" {
			respondWithError(w, r, log, http.StatusBadRequest, ErrMissingToken.Error())
			return
		}

		if fileByte, ok := FileCache.Load(id); ok {
			fileData := fileByte.([]byte)
			if len(fileData) == 0 {
				log.Warn("File found in cache, but data length is 0", slog.String("id", id))
				serveFileFromStorage(w, r, log, flGeter, id, token)
				return
			}

			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
			w.Header().Set("Content-Type", determineContentType(fileData))

			w.WriteHeader(http.StatusOK)
			log.Info("Served file (headers) from cache", slog.String("id", id))
			return
		}

		serveFileFromStorage(w, r, log, flGeter, id, token)
	}
}

func serveFileFromStorage(w http.ResponseWriter, r *http.Request, log *slog.Logger, flGeter FileGeter, id string, token string) {
	jsonData, err := flGeter.GetFile(id, token)
	if errors.Is(err, storage.ErrNotFound) {
		log.Info("file not found", slog.String("id", id), sl.Err(err))
		respondWithError(w, r, log, http.StatusNotFound, "file not found")
		return
	}

	if errors.Is(err, storage.ErrPermissionDenied) {
		log.Info("permission denied", slog.String("id", id), sl.Err(err))
		respondWithError(w, r, log, http.StatusForbidden, "permission denied")
		return
	}

	if errors.Is(err, storage.ErrUnauthorized) {
		log.Info("unauthorized", slog.String("id", id), sl.Err(err))
		respondWithError(w, r, log, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err != nil {
		log.Error("failed to get file metadata", slog.String("id", id), sl.Err(err))
		respondWithError(w, r, log, http.StatusInternalServerError, "failed to get file metadata")
		return
	}
	if len(jsonData) > maxMetadataLength {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		log.Info("Served metadata (headers) from FileGeter", slog.String("id", id))
		return
	}

	err = serveFileFromUploadsHead(w, r, id)
	if err != nil {
		log.Error("failed to serve file from disk", slog.String("id", id), sl.Err(err))
		respondWithError(w, r, log, http.StatusInternalServerError, ErrDiskError.Error())
		return
	}
	log.Info("Served file headers from disk", slog.String("id", id))
}

func serveFileFromUploadsHead(w http.ResponseWriter, r *http.Request, id string) error {
	uploadDir := "./uploads"

	files, err := os.ReadDir(uploadDir)

	if err != nil {
		return fmt.Errorf("failed to list upload directory: %w", err)
	}

	var foundFileName string

	for _, file := range files {
		if strings.HasPrefix(file.Name(), id) {
			foundFileName = file.Name()
			break
		}
	}

	if foundFileName == "" {
		return fmt.Errorf("file not found on disk")
	}

	filePath := filepath.Join(uploadDir, foundFileName)

	fileInfo, err := os.Stat(filePath)

	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Content-Type", determineContentTypeFromPath(filePath))
	w.WriteHeader(http.StatusOK)
	return nil
}

func respondWithError(w http.ResponseWriter, r *http.Request, log *slog.Logger, code int, message string) {
	log.Error(message)
	render.Status(r, code)
	render.JSON(w, r, ErrorData{Error: Error{Code: code, Text: message}})
}

func determineContentTypeFromPath(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		return "application/json"
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	default:
		return defaultContentType
	}
}

func determineContentType(fileByte []byte) string {
	contentType := http.DetectContentType(fileByte)
	return contentType
}
