package delete

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
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"strings"
)

const uploadsDir = "./uploads"

type FileDeleter interface {
	DeleteFile(id, token string) error
}

func Delete(log *slog.Logger, flDeleter FileDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.user.register.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", middleware.GetReqID(r.Context())),
		)

		id := chi.URLParam(r, "id")
		if id == "" {
			log.Error("id is missing")
			resp.ErrorMsg(http.StatusBadRequest, "id is required")
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "id is required"))
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Error("token is missing")
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "token is required"))
			return
		}

		err := flDeleter.DeleteFile(id, token)
		if errors.Is(err, storage.ErrNotFound) {
			log.Info("no such file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "no such file"))
			return
		}
		if errors.Is(err, storage.ErrPermissionDenied) {
			log.Info("no such file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusForbidden, "no permission"))
			return
		}
		if err != nil {
			log.Error("failed to delete file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(
				http.StatusInternalServerError,
				"failed to delete file",
			))
			return
		}

		err = deleteFileFromDisk(id)
		if err != nil {
			log.Error("failed to delete file from disk", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(
				http.StatusInternalServerError,
				"failed to delete file from disk",
			))
			return
		}

		log.Info("file deleted")

		responseOk(w, r, token)
	}
}

func responseOk(w http.ResponseWriter, r *http.Request, token string) {
	response := map[string]map[string]bool{
		"response": {
			token: true,
		},
	}

	render.JSON(w, r, response)
}

func deleteFileFromDisk(id string) error {
	files, err := os.ReadDir(uploadsDir)
	if err != nil {
		return fmt.Errorf("failed to read upload directory: %w", err)
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), id) {
			filePath := filepath.Join(uploadsDir, file.Name())
			err := os.Remove(filePath)
			if err != nil {
				return fmt.Errorf("failed to delete file %s: %w", filePath, err)
			}
			return nil
		}
	}

	return fmt.Errorf("file with id %s not found in upload directory", id)
}
