package postgresql

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq" // init postgres driver
	"rest-book/internal/config"
	"rest-book/internal/http-server/handlers/files/save"
	"rest-book/internal/storage"
	"time"
)

type Storage struct {
	DB         *sql.DB
	AdminToken string //TODO: replace
}

func New(dbConfig config.DbConfig, admToken string) (*Storage, error) {
	const op = "storage.postgresql.New"

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbConfig.Host, dbConfig.Port, dbConfig.Username, dbConfig.Password, dbConfig.DBName)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	err = CreateTables(db)
	if err != nil {
		return nil, err
	}

	err = DeleteTokenTrigger(db)
	if err != nil {
		return nil, err
	}

	return &Storage{DB: db, AdminToken: admToken}, nil
}

func CreateTables(db *sql.DB) error {
	const op = "storage.postgresql.CreateTables"

	stmtUserTable, err := db.Prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            login TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            token TEXT
        );
    `)
	if err != nil {
		return fmt.Errorf("%s: prepare user table: %w", op, err)
	}
	_, err = stmtUserTable.Exec()
	if err != nil {
		return fmt.Errorf("%s: execute user table: %w", op, err)
	}

	stmtFileTable, err := db.Prepare(`
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            file BOOLEAN NOT NULL DEFAULT FALSE,
            public BOOLEAN NOT NULL DEFAULT FALSE,
            mime TEXT NOT NULL,
            json JSONB,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
        );
    `)
	if err != nil {
		return fmt.Errorf("%s: prepare files table: %w", op, err)
	}
	_, err = stmtFileTable.Exec()
	if err != nil {
		return fmt.Errorf("%s: execute files table: %w", op, err)
	}

	stmtGrantTable, err := db.Prepare(`
        CREATE TABLE IF NOT EXISTS file_grants (
            file_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (file_id, user_id)
        );
    `)

	if err != nil {
		return fmt.Errorf("%s: prepare file_grants table: %w", op, err)
	}
	_, err = stmtGrantTable.Exec()
	if err != nil {
		return fmt.Errorf("%s: execute file_grants table: %w", op, err)
	}

	stmtSessionTable, err := db.Prepare(`
		CREATE TABLE IF NOT EXISTS sessions (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id),
			token VARCHAR(255) NOT NULL UNIQUE,
			created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc'),
			expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
		);
    `)
	if err != nil {
		return fmt.Errorf("%s: prepare files table: %w", op, err)
	}
	_, err = stmtSessionTable.Exec()
	if err != nil {
		return fmt.Errorf("%s: execute files table: %w", op, err)
	}

	return nil
}

func Index(db *sql.DB) error {
	const op = "storage.postgresql.Index"
	stmtIndex, err := db.Prepare(`
        CREATE INDEX IF NOT EXISTS idx_name ON url(alias);
    `)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmtIndex.Exec()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func DeleteTokenTrigger(db *sql.DB) error {
	const op = "storage.postgresql.DeleteTokenTrigger"

	var isTriggerExists int
	err := db.QueryRow("SELECT count(*) FROM pg_trigger WHERE tgname = 'sessions_cleanup';").Scan(&isTriggerExists)
	if err != nil {
		return fmt.Errorf("%s: failed to check trigger existence: %w", op, err)
	}

	if isTriggerExists == 0 {
		_, err = db.Exec(`
			   CREATE OR REPLACE FUNCTION delete_expired_sessions()
			   RETURNS TRIGGER AS $$
			   BEGIN
				DELETE FROM sessions WHERE expires_at <= NOW();
				RETURN NEW;
			   END;
			   $$ LANGUAGE plpgsql;
			
			   CREATE TRIGGER sessions_cleanup
			   AFTER INSERT OR UPDATE OR DELETE ON sessions
			   FOR EACH ROW
			   EXECUTE FUNCTION delete_expired_sessions();
			  `)
		if err != nil {
			return fmt.Errorf("%s: failed to create trigger: %w", op, err)
		}
	}

	return nil
}

func (s *Storage) AddUser(login, password, salt string) error {
	const op = "storage.postgresql.SaveUrl"

	stmt, err := s.DB.Prepare("INSERT INTO users(login, password, salt) VALUES($1, $2, $3);")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(login, password, salt)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // PostgreSQL error code for unique violation
				return fmt.Errorf("%s: %w", op, storage.ErrAlreadyExists)
			}
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) AuthUser(login string) (int64, string, string, error) {
	const op = "storage.postgresql.AuthUser"

	stmt, err := s.DB.Prepare("SELECT id, password, salt FROM users WHERE login = $1")
	if err != nil {
		return 0, "", "", fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var id int64
	var password, salt string
	err = stmt.QueryRow(login).Scan(&id, &password, &salt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", "", storage.ErrNotFound
		}
		return 0, "", "", fmt.Errorf("%s: %w", op, err)
	}

	return id, password, salt, nil
}

func (s *Storage) CreateSession(userID int64, token string, expiresAt time.Time) error {
	const op = "storage.postgresql.CreateSession"

	stmt, err := s.DB.Prepare("INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID, token, expiresAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) DeleteSession(token string) error {
	const op = "storage.postgresql.DeleteSession"

	stmt, err := s.DB.Prepare("DELETE FROM sessions WHERE token = $1")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if rowsAffected == 0 {
		return storage.ErrNotFound
	}

	return nil
}

func (s *Storage) SaveFile(meta save.Meta, jsonData interface{}) (string, error) {
	const op = "storage.postgresql.SaveFile"

	isSession := s.sessionExists(meta.Token)
	if !isSession || meta.Token != s.AdminToken {
		return "", fmt.Errorf("%s: incorrect token", op)
	}

	query := `
		  INSERT INTO files (
		   id, 
		   file_name, 
		   file, 
		   public, 
		   mime, 
		   json
		   ) 
		  VALUES ($1, $2, $3, $4, $5, $6)
		  RETURNING id
		 `

	var jsonNullString sql.NullString

	if jsonData == nil {
		jsonNullString = sql.NullString{Valid: false}
	} else {
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return "", fmt.Errorf("%s: error marshaling JSON: %w", op, err)
		}
		jsonString := string(jsonBytes)
		jsonNullString = sql.NullString{String: jsonString, Valid: true}
	}

	stmt, err := s.DB.Prepare(query)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	id, err := s.generateUniqueFileID()
	if err != nil {
		return "", fmt.Errorf("%s: error marshaling JSON: %w", op, err)
	}

	_, err = stmt.Exec(id, meta.Name, meta.File, meta.Public, meta.Mime, jsonNullString)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = s.GrantFileAccess(id, meta.Grant)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) GrantFileAccess(fileID string, grants []string) error {
	const op = "storage.postgresql.GrantFileAccess"

	if len(grants) == 0 {
		return nil
	}

	t, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("%s: failed to start transaction: %w", op, err)
	}
	defer func() {
		if err != nil {
			if rollbackErr := t.Rollback(); rollbackErr != nil {
				fmt.Printf("%s: failed to rollback transaction: %v\n", op, rollbackErr)
			}
			return
		}
		if commitErr := t.Commit(); commitErr != nil {
			err = fmt.Errorf("%s: failed to commit transaction: %w", op, commitErr)
		}
	}()

	query := `
        INSERT INTO file_grants (file_id, user_id)
        VALUES ($1, (SELECT id FROM users WHERE login = $2))
    `
	stmt, err := t.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: failed to prepare statement: %w", op, err)
	}
	defer stmt.Close()

	for _, login := range grants {
		_, err = stmt.Exec(fileID, login)
		if err != nil {
			return fmt.Errorf("%s: failed to execute statement for login %s: %w", op, login, err)
		}
	}

	return nil
}

func (s *Storage) generateUniqueFileID() (string, error) {
	for i := 0; i < 10; i++ {
		id, err := generateRandomID(32)
		if err != nil {
			return "", err
		}
		exists, err := s.fileIDExists(id)
		if err != nil {
			return "", err
		}
		if !exists {
			return id, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique ID after multiple attempts")
}

func generateRandomID(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Storage) fileIDExists(id string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM files WHERE id = $1)`
	var exists bool
	err := s.DB.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if ID exists: %w", err)
	}
	return exists, nil
}

func (s *Storage) sessionExists(token string) bool {
	query := `SELECT EXISTS (SELECT 1 FROM sessions WHERE token = $1)`
	var exists bool
	err := s.DB.QueryRow(query, token).Scan(&exists)
	if err != nil {
		return false
	}
	fmt.Println("SESSION EXISTS", exists)
	return exists
}

func (s *Storage) DeleteFile(id, token string) error {
	const op = "storage.postgresql.DeleteFile"

	isSession := s.sessionExists(token)
	if !isSession {
		return fmt.Errorf("%s: %w", op, storage.ErrPermissionDenied)
	}
	stmt, err := s.DB.Prepare("DELETE FROM files WHERE id = $1")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: failed to get rows affected: %w", op, err)
	}

	if rowsAffected == 0 {
		return storage.ErrNotFound
	}

	return nil
}

func (s *Storage) GetFile(id, token string) (string, error) {
	const op = "storage.postgresql.GetFile"

	access, err := s.hasAccess(id, token)
	if err != nil || !access || token != s.AdminToken {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	queryFileData := `
	  SELECT json
	  FROM files
	  WHERE id = $1
	 `
	var jsonData string
	err = s.DB.QueryRow(queryFileData, id).Scan(&jsonData)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%s: file not found: %w", op, storage.ErrNotFound)
		}
		return "", fmt.Errorf("%s: failed to get file data: %w", op, err)
	}

	return jsonData, nil
}

type FileData struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Mime    string    `json:"mime"`
	File    bool      `json:"file"`
	Public  bool      `json:"public"`
	Created time.Time `json:"created"`
	Grant   []string  `json:"grant"`
}

func (s *Storage) GetFiles(token, key, value string, limit, offset int) ([]FileData, error) {
	const op = "storage.postgresql.GetFiles"

	access := s.sessionExists(token)
	if !access || token != s.AdminToken {
		return nil, fmt.Errorf("%s: %w", op, errors.New("invalid token"))
	}

	queryFileData := `
        SELECT id, file_name, mime, file, public, created_at
        FROM files
        WHERE id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `

	rows, err := s.DB.Query(queryFileData, value, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to execute query: %w", op, err)
	}
	defer rows.Close()

	var files []FileData
	for rows.Next() {
		var file FileData

		err := rows.Scan(
			&file.ID,
			&file.Name,
			&file.Mime,
			&file.File,
			&file.Public,
			&file.Created,
		)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to scan row: %w", op, err)
		}

		grants, err := s.getFileGrants(file.ID)
		if err != nil {
		} else {
			file.Grant = grants
		}

		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: error during rows iteration: %w", op, err)
	}

	return files, nil
}

func (s *Storage) getFileGrants(fileID string) ([]string, error) {
	const op = "storage.postgresql.getFileGrants"

	query := `
        SELECT u.login
        FROM file_grants fg
        JOIN users u ON fg.user_id = u.id
        WHERE fg.file_id = $1
    `

	rows, err := s.DB.Query(query, fileID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to execute query: %w", op, err)
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return nil, fmt.Errorf("%s: failed to scan row: %w", op, err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: error during rows iteration: %w", op, err)
	}

	return users, nil
}

func (s *Storage) hasAccess(id, token string) (bool, error) {
	const op = "storage.postgresql.hasAccess"

	queryUserID := `
		  SELECT user_id
		  FROM sessions
		  WHERE token = $1
		 `
	var userID int
	err := s.DB.QueryRow(queryUserID, token).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: invalid token: %w", op, storage.ErrPermissionDenied)
		}
		return false, fmt.Errorf("%s: failed to get user_id from sessions: %w", op, err)
	}

	queryFileAccess := `
			  SELECT 1
			  FROM file_grants
			  WHERE file_id = $1 AND user_id = $2
			 `
	var hasAccess int
	err = s.DB.QueryRow(queryFileAccess, id, userID).Scan(&hasAccess)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: user does not have access to this file: %w", op, storage.ErrPermissionDenied)
		}
		return false, fmt.Errorf("%s: failed to check file access: %w", op, err)
	}
	return true, nil
}
