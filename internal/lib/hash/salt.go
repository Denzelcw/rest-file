package hash

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
)

func generateRandomSalt(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b), nil
}

func HashPasswordWithSalt(password string) (string, string, error) {
	salt, err := generateRandomSalt(16)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate hash: %w", err)
	}

	saltedPassword := password + salt

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedPassword), salt, nil
}
