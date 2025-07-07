package storage

import (
	"errors"
)

var (
	ErrNotFound         = errors.New("user not found")
	ErrAlreadyExists    = errors.New("user exists")
	ErrPermissionDenied = errors.New("permission denied")
	ErrUnauthorized     = errors.New("unauthorized ")
)
