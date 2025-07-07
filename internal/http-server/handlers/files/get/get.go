package get

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"rest-book/internal/http-server/handlers/files/cache"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"strings"
)

const uploadsDir = "./uploads"

type FileGeter interface {
	GetFile(id, token string) (string, error)
}

func GetDoc(log *slog.Logger, flGeter FileGeter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.file.get.Get"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", middleware.GetReqID(r.Context())),
		)

		id := chi.URLParam(r, "id")
		if id == "" {
			log.Error("id is missing")
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "id is required"))
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Error("token is missing")
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "token is required"))
			return
		}

		if file, ok := cache.FileCache.Load(id); ok {
			if byteData, ok := file.([]byte); ok {
				_, err := w.Write(byteData)
				if err != nil {
					log.Error("can't get from cache", sl.Err(err))
					render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "can't get file"))
				}
				return
			}
			if jsonData, ok := file.(string); ok {
				responseOk(w, r, jsonData)
			}
		}

		jsonData, err := flGeter.GetFile(id, token)
		if errors.Is(err, storage.ErrNotFound) {
			log.Info("file not found", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusNotFound, "file not found"))
			return
		}
		if errors.Is(err, storage.ErrPermissionDenied) {
			log.Info("permission denied", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusForbidden, "permission denied"))
			return
		}
		if err != nil {
			log.Error("failed to get file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to get file"))
			return
		}

		if len(jsonData) > 2 {
			responseOk(w, r, jsonData)
		}

		err = serveFileFromUploads(w, r, id)
		if err != nil {
			log.Error("failed to serve file from disk", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to get file"))
			return
		}
	}
}

func serveFileFromUploads(w http.ResponseWriter, r *http.Request, id string) error {
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		return fmt.Errorf("failed to read upload directory: %w", err)
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), id) {
			filePath := filepath.Join(uploadsDir, file.Name())
			http.ServeFile(w, r, filePath)
			return nil
		}
	}

	return fmt.Errorf("file with id %s not found in upload directory", id)
}

func responseOk(w http.ResponseWriter, r *http.Request, jsonData string) {
	response := map[string]interface{}{
		"data": jsonData,
	}

	render.JSON(w, r, response)
}
