package close_session

import (
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"log/slog"
	"net/http"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
)

type SessionDeleter interface {
	DeleteSession(token string) error
}

func Close(log *slog.Logger, sessDeleter SessionDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.user.register.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", middleware.GetReqID(r.Context())),
		)

		token := chi.URLParam(r, "token")
		if token == "" {
			log.Error("token is missing")
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "Token is required"))
			return
		}

		err := sessDeleter.DeleteSession(token)
		if errors.Is(err, storage.ErrNotFound) {
			log.Info("no such token", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusUnauthorized, "no such token"))
			return
		}
		if err != nil {
			log.Error("failed to register user", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to delete session"))
			return
		}

		log.Info("user registered")

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
