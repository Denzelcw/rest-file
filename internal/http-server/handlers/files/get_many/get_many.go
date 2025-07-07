package get_many

import (
	"errors"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"log/slog"
	"net/http"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"rest-book/internal/storage/postgresql"
	"strconv"
)

type Data struct {
	Data DocsWrapper `json:"data"`
}

type DocsWrapper struct {
	Docs []postgresql.FileData `json:"docs"`
}

type Request struct {
	Token  string `form:"token" validate:"required,token"`
	Key    string `form:"key" validate:"required,key"`
	Value  string `form:"value" validate:"required,value"`
	Limit  int    `form:"limit" validate:"required,limit"`
	Offset int    `form:"offset" validate:"required,offset"`
}

type FilesGeter interface {
	GetFiles(token, key, value string, limit, offset int) ([]postgresql.FileData, error)
}

func GetDocs(log *slog.Logger, flsGeter FilesGeter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.file.get.GetDocs"

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
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "Invalid limit value"))
			return
		}

		offset, err := strconv.Atoi(offsetStr)
		if err != nil && offsetStr != "" {
			slog.Error("Invalid offset value", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "Invalid offset value"))
			return
		}

		files, err := flsGeter.GetFiles(token, key, value, limit, offset)
		if errors.Is(err, storage.ErrNotFound) {
			render.JSON(w, r, resp.ErrorMsg(http.StatusNotFound, "files are not found"))
			return
		}
		if errors.Is(err, storage.ErrPermissionDenied) {
			render.JSON(w, r, resp.ErrorMsg(http.StatusForbidden, "permission denied"))
			return
		}
		if errors.Is(err, storage.ErrUnauthorized) {
			render.JSON(w, r, resp.ErrorMsg(http.StatusUnauthorized, "unauthorized"))
			return
		}
		if err != nil {
			log.Error("failed to get file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to get file"))
			return
		}

		data, err := ConvertToJSON(files)
		if err != nil {
			log.Error("failed to convert to json", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to get file"))
			return
		}

		render.JSON(w, r, data)
	}
}

func ConvertToJSON(files []postgresql.FileData) (Data, error) {
	wrapper := DocsWrapper{
		Docs: files,
	}

	data := Data{
		Data: wrapper,
	}

	return data, nil
}
