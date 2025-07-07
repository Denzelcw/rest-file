package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"rest-book/internal/lib/api/form_decoder"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"time"
)

type Request struct {
	Login    string `form:"login" validate:"required,login"`
	Password string `form:"password" validate:"required,password"`
}

type Response struct {
	ResponseData ResponseData `json:"response"`
}

type ResponseData struct {
	Token string `json:"token,omitempty"`
}

type IAuth interface {
	AuthUser(login string) (int64, string, string, error)
	CreateSession(userID int64, token string, expiresAt time.Time) error
}

func Auth(log *slog.Logger, usrAuth IAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.user.auth.Auth"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", middleware.GetReqID(r.Context())),
		)

		var req Request

		if err := r.ParseForm(); err != nil {
			log.Error("failed to parse form", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, "fields are not valid"))
			return
		}

		if err := form_decoder.DecodeForm(r, &req); err != nil {
			log.Error("failed to decode form", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to auth user"))
			return
		}

		log.Info("request body decoded", slog.Any("request", req))

		id, hash, salt, err := usrAuth.AuthUser(req.Login)
		if errors.Is(err, storage.ErrNotFound) {
			log.Info("unknown login", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusConflict, "unknown login or password"))
			return
		}
		if err != nil {
			log.Error("failed to auth user", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to auth user"))
			return
		}

		err = checkPassword(req.Password, hash, salt)
		if err != nil {
			log.Error("unknown login or password", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusUnauthorized, "unknown login or password"))
			return
		}

		token, err := generateToken(usrAuth, id)
		if err != nil {
			log.Error("failed to generate token", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "Failed to auth user"))
			return
		}

		log.Info("user authed")

		responseOk(w, r, token)
	}
}

func responseOk(w http.ResponseWriter, r *http.Request, token string) {
	response := Response{
		ResponseData: ResponseData{
			Token: token,
		},
	}

	render.JSON(w, r, response)
}

func checkPassword(password string, hashedPassword string, salt string) error {
	saltedPassword := password + salt

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(saltedPassword))
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func generateToken(usrAuth IAuth, userId int64) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(b)

	expiresAt := time.Now().Add(time.Hour)

	err = usrAuth.CreateSession(userId, token, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return token, nil
}
