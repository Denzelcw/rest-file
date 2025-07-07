package save

import (
	"bytes"
	"encoding/json"
	"github.com/go-chi/render"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"rest-book/internal/http-server/handlers/files/cache"
	resp "rest-book/internal/lib/api/response"
	"rest-book/internal/lib/logger/sl"
)

type Meta struct {
	Name   string   `json:"name"`
	File   bool     `json:"file"`
	Public bool     `json:"public"`
	Token  string   `json:"token"`
	Mime   string   `json:"mime"`
	Grant  []string `json:"grant"`
}

type ResponseData struct {
	JSON interface{} `json:"json,omitempty"`
	File string      `json:"file"`
}

type Response struct {
	Data ResponseData `json:"data"`
}

type FileSaver interface {
	SaveFile(meta Meta, jsonData interface{}) (string, error)
	DeleteFile(id, token string) error
}

func Save(log *slog.Logger, flSaver FileSaver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.files.save.Save"

		log = log.With(
			slog.String("op", op),
			slog.String("request_url", r.URL.Path),
		)

		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			log.Error("failed to parse multipart form", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}

		metaJSON := r.FormValue("meta")
		var meta Meta
		err = json.Unmarshal([]byte(metaJSON), &meta)
		if err != nil {
			log.Error("failed to unmarshal meta", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}

		jsonData := r.FormValue("json")
		var jsonInterface interface{}
		if jsonData != "" {
			err = json.Unmarshal([]byte(jsonData), &jsonInterface)
			if err != nil {
				log.Error("failed to unmarshal json data", sl.Err(err))
				render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
				return
			}
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			log.Error("failed to get file", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}
		defer file.Close()

		if !meta.File && len(jsonData) > 0 {
			id, err := flSaver.SaveFile(meta, jsonData)
			if err != nil {
				log.Error("failed to add json to db", sl.Err(err))
				render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save json"))
				return
			}
			cache.FileCache.Store(id, jsonData)
		}

		uploadDir := "./uploads"
		err = os.MkdirAll(uploadDir, os.ModeDir|0755)
		if err != nil {
			log.Error("failed to create upload directory", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}

		id, err := flSaver.SaveFile(meta, jsonData)
		if err != nil {
			log.Error("failed to add file to db", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}
		fileData, err := io.ReadAll(file)
		if err != nil {
			log.Error("failed to read file data", sl.Err(err))
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}
		addCache(fileData, id)

		fileExtension := filepath.Ext(header.Filename)
		filePath := filepath.Join(uploadDir, id+fileExtension)

		err = os.WriteFile(filePath, fileData, 0644)
		if err != nil {
			log.Error("failed to write file to disk", sl.Err(err))
			deleteErr := flSaver.DeleteFile(id, meta.Token)
			if deleteErr != nil {
				log.Error("failed to delete file metadata after disk write failure", sl.Err(deleteErr))
			}
			render.JSON(w, r, resp.ErrorMsg(http.StatusInternalServerError, "couldn't save file"))
			return
		}

		log.Info("document uploaded successfully")

		responseOk(w, r, header.Filename, jsonInterface)
	}
}

func addCache(file []byte, id string) {
	reader := bytes.NewReader(file)
	dst := &bytes.Buffer{}

	_, err := io.Copy(dst, reader)
	if err != nil {
		slog.Error("Couldn't save to cache:", err)
	}

	cache.FileCache.Store(id, dst.Bytes())
}

func responseOk(w http.ResponseWriter, r *http.Request, fileName string, jsonInterface interface{}) {
	response := Response{
		Data: ResponseData{
			JSON: jsonInterface,
			File: fileName,
		},
	}

	render.JSON(w, r, response)
}
