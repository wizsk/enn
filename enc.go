package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (app *App) encryptFile(inputPath string) ([]byte, error) {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(app.config.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Optional but recommended: authenticate filename
	aad := []byte(filepath.Base(inputPath))

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	var buf bytes.Buffer
	buf.Grow(len(fileMagic) + 1 + len(nonce) + len(ciphertext))
	buf.WriteString(fileMagic)
	buf.WriteByte(fileVer)
	buf.Write(nonce)
	buf.Write(ciphertext)

	return buf.Bytes(), nil
}

func (app *App) decryptFile(inputPath string) ([]byte, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 4+1 {
		return nil, errors.New("ciphertext too short")
	}

	if string(data[:4]) != fileMagic {
		return nil, errors.New("invalid file magic")
	}

	if data[4] != fileVer {
		return nil, errors.New("unsupported file version")
	}

	block, err := aes.NewCipher(app.config.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	offset := 5
	nonceSize := gcm.NonceSize()

	if len(data) < offset+nonceSize {
		return nil, errors.New("invalid ciphertext")
	}

	nonce := data[offset : offset+nonceSize]
	ciphertext := data[offset+nonceSize:]

	aad := []byte(strings.TrimSuffix(filepath.Base(inputPath), ".enc"))

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decryption failed (wrong password or corrupted data)")
	}
	return plaintext, nil
}
