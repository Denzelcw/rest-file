package head_docs

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5/middleware"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"rest-book/internal/storage/postgresql"
)

type FilesGeter interface {
	GetFiles(token, key, value string, limit, offset int) ([]postgresql.FileData, error)
}

func GetDocsHead(log *slog.Logger, flsGeter FilesGeter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.file.head.HeadDocs"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", middleware.GetReqID(r.Context())),
		)

		query := r.URL.Query()

		token := query.Get("token")
		key := query.Get("key")
		value := query.Get("value")

		limitStr := query.Get("limit")
		offsetStr := query.Get("offset")

		limit, err := strconv.Atoi(limitStr)
		if err != nil && limitStr != "" {
			slog.Error("Invalid limit value", sl.Err(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		offset, err := strconv.Atoi(offsetStr)
		if err != nil && offsetStr != "" {
			slog.Error("Invalid offset value", sl.Err(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		files, err := flsGeter.GetFiles(token, key, value, limit, offset)
		if errors.Is(err, storage.ErrNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if errors.Is(err, storage.ErrPermissionDenied) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if errors.Is(err, storage.ErrUnauthorized) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Error("failed to get file", sl.Err(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(files) > 0 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}
