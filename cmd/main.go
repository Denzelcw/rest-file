package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"
	"net/http"
	"os"
	"rest-book/internal/config"
	"rest-book/internal/http-server/handlers/files/delete"
	"rest-book/internal/http-server/handlers/files/get"
	"rest-book/internal/http-server/handlers/files/get_many"
	"rest-book/internal/http-server/handlers/files/head_doc"
	"rest-book/internal/http-server/handlers/files/head_docs"
	"rest-book/internal/http-server/handlers/files/save"
	"rest-book/internal/http-server/handlers/user/auth"
	"rest-book/internal/http-server/handlers/user/close_session"
	"rest-book/internal/http-server/handlers/user/reigster"
	"rest-book/internal/http-server/middleware/logger"
	"rest-book/internal/lib/logger/sl"
	"rest-book/internal/storage/postgresql"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {

	cfg := config.MustLoad()

	log := setUpLogger(cfg.Env)

	storage, err := postgresql.New(cfg.DbConfig, cfg.AdminToken)
	if err != nil {
		log.Error("failed to init storage: ", sl.Err(err))
		os.Exit(1)
	}

	defer storage.DB.Close()

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(logger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Post("/register", reigster.New(log, storage))
	router.Post("/auth", auth.Auth(log, storage))
	router.Post("/docs", save.Save(log, storage))
	router.Get("/docs", get_many.GetDocs(log, storage))
	router.Get("/docs/{id}", get.GetDoc(log, storage))
	router.Head("/docs/{id}", head_doc.GetDocHead(log, storage))
	router.Head("/docs/{id}", head_docs.GetDocsHead(log, storage))
	router.Delete("/docs/{id}", delete.Delete(log, storage))
	router.Delete("/auth/{token}", close_session.Close(log, storage))

	log.Info("starting server", slog.String("address", cfg.Address))

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Error("failed to start server")
	}

}

func setUpLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return log
}
