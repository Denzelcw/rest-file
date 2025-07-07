package reigster

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"log/slog"
	"net/http"
	"regexp"
	"rest-book/internal/lib/api/form_decoder"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/hash"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage"
	"unicode"
)

type Request struct {
	Login    string `form:"login" validate:"required,login"`
	Password string `form:"password" validate:"required,password"`
}

type Response struct {
	ResponseData ResponseData `json:"response"`
}

type ResponseData struct {
	Login string `json:"login,omitempty"`
}

type Register interface {
	AddUser(login, password, salt string) error
}

func New(log *slog.Logger, usrRegister Register) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.user.register.New"

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
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to register"))
			return
		}

		login := req.Login

		if err := validateLogin(login); err != nil {
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, err.Error()))
			return
		}

		if err := validatePassword(req.Password); err != nil {
			render.JSON(w, r, resp.ErrorMsg(http.StatusBadRequest, err.Error()))
			return
		}

		hashPassword, salt, err := hash.HashPasswordWithSalt(req.Password)
		if err != nil {
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to register user"))
			return
		}

		err = usrRegister.AddUser(login, hashPassword, salt)
		if errors.Is(err, storage.ErrAlreadyExists) {
			log.Info("user already exists", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusConflict, "user already exists"))
			return
		}
		if err != nil {
			log.Error("failed to register user", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "failed to register user"))
			return
		}

		log.Info("user registered")

		responseOk(w, r, login)
	}
}

func responseOk(w http.ResponseWriter, r *http.Request, login string) {
	response := Response{
		ResponseData: ResponseData{
			Login: login,
		},
	}

	render.JSON(w, r, response)
}

func validateLogin(login string) error {
	if len(login) < 8 {
		return fmt.Errorf("Login must be at least 8 characters long")
	}

	pattern := `^[a-zA-Z0-9]+$`
	matched, err := regexp.MatchString(pattern, login)
	if err != nil {
		return fmt.Errorf("Error during regex match: %w", err)
	}

	if !matched {
		return fmt.Errorf("Login must contain only Latin letters and digits")
	}

	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("Password must be at least 8 characters long")
	}

	hasUpper := 0
	hasLower := 0
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		if unicode.IsUpper(r) {
			hasUpper++
		} else if unicode.IsLower(r) {
			hasLower++
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	if hasUpper < 1 {
		return fmt.Errorf("Password must contain at least one uppercase letter")
	}
	if hasLower < 1 {
		return fmt.Errorf("Password must contain at least one lowercase letter")
	}

	if !hasDigit {
		return fmt.Errorf("Password must contain at least one digit")
	}

	if !hasSpecial {
		return fmt.Errorf("Password must contain at least one special character (non-letter and non-digit)")
	}

	if hasUpper+hasLower < 2 {
		return fmt.Errorf("Password must contain at least 2 letters with different registers")
	}

	return nil
}
