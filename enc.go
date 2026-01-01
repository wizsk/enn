package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	fileMagic = "NENC"
	fileVer   = byte(1)

	appSalt = "enn-encryption-v1"
)

// if manifest is new then all the notes are naturally forcefully encryped
// btw, manifest is never modified
func (app *App) encryptNotes(manifest *FileManifest) (*FileManifest, error) {
	app.log("Starting encryption process")

	mdFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	if err != nil {
		return nil, err
	}

	if len(mdFiles) == 0 {
		app.warning("No .md files found")
		return nil, nil
	}

	successCount := 0
	skippedCount := 0

	maxWorkers := min(runtime.NumCPU()*2, len(mdFiles))
	jobs := make(chan string, maxWorkers)

	// do not buffer
	type result struct {
		suc bool
		err error
		fn  string
		fi  FileInfo
	}
	done := make(chan result)

	for range maxWorkers {
		go func(j <-chan string, res chan<- result) {
			for mdFile := range j {
				filename := filepath.Base(mdFile)
				encryptedFile := mdFile + ".enc"

				// Get file info
				fileInfo, err := os.Stat(mdFile)
				if err != nil {
					res <- result{err: fmt.Errorf("failed to stat %s: %w", filename, err)}
				}

				// Calculate hash
				hash, err := app.fileHash(mdFile)
				if err != nil {
					res <- result{err: fmt.Errorf("failed to hash %s: %w", filename, err)}
				}

				// Check if encryption is needed
				if oldInfo, exists := manifest.Files[filename]; exists {
					if oldInfo.Hash == hash && oldInfo.Encrypted {
						res <- result{suc: false, fn: filename, fi: oldInfo}
						continue
					}
				}

				app.info(fmt.Sprintf("Encrypting: %s", filename))

				// Backup existing encrypted file
				backupFile := encryptedFile + ".backup"
				if _, err := os.Stat(encryptedFile); err == nil {
					if err := app.copyFile(encryptedFile, backupFile); err != nil {
						res <- result{suc: false, err: fmt.Errorf("failed to backup %s: %w", filename, err)}
					}
				}

				// Encrypt file
				if err := app.encryptFile(mdFile, encryptedFile); err != nil {
					os.Remove(encryptedFile)
					if _, err := os.Stat(backupFile); err == nil {
						os.Rename(backupFile, encryptedFile)
					}
					res <- result{suc: false, err: fmt.Errorf("failed to encrypt %s: %w", filename, err)}
				}

				// Verify encryption
				if err := app.verifyEncryption(mdFile, encryptedFile); err != nil {
					os.Remove(encryptedFile)
					if _, err := os.Stat(backupFile); err == nil {
						os.Rename(backupFile, encryptedFile)
					}
					res <- result{suc: false, err: fmt.Errorf("verification failed for %s: %w", filename, err)}
				}

				// Success - remove backup
				os.Remove(backupFile)

				app.success(fmt.Sprintf("Encrypted and verified: %s", filename))
				// Update manifest
				fi := FileInfo{
					// Name:         filename,
					Hash:         hash,
					LastModified: fileInfo.ModTime(),
					Encrypted:    true,
				}

				res <- result{true, nil, filename, fi}
			}
		}(jobs, done)
	}

	go func() {
		for _, mdFile := range mdFiles {
			jobs <- mdFile
		}
		close(jobs)
	}()

	errs := []error{}
	newMenifest := &FileManifest{make(map[string]FileInfo, len(mdFiles))}
	for range mdFiles {
		val := <-done
		if val.err != nil {
			errs = append(errs, val.err)
			continue
		} else if val.suc {
			successCount++
		} else {
			skippedCount++
		}
		newMenifest.Files[val.fn] = val.fi
	}

	if len(errs) > 0 {
		for _, err := range errs {
			app.errorMsg(err.Error())
		}
		return newMenifest, fmt.Errorf("While encrypting errs encountered")
	}

	if successCount > 0 || skippedCount > 0 {
		app.success(fmt.Sprintf("Encryption summary: %d encrypted, %d unchanged", successCount, skippedCount))
	}

	return newMenifest, nil
}

func (app *App) encryptFile(inputPath, outputPath string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(app.config.Key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
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

	return os.WriteFile(outputPath, buf.Bytes(), 0600)
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
