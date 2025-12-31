package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/pbkdf2"
)

// if manifest is new then all the notes are naturally forcefully encryped
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
	// Read plaintext
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Derive key from password
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := pbkdf2.Key(app.config.Password, salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write: salt + ciphertext
	output := append(salt, ciphertext...)

	return os.WriteFile(outputPath, output, 0644)
}

func (app *App) decryptFile(inputPath string) ([]byte, error) {
	// Read encrypted data
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 32 {
		return nil, fmt.Errorf("invalid encrypted file")
	}

	// Extract salt
	salt := data[:32]
	ciphertext := data[32:]

	// Derive key
	key := pbkdf2.Key(app.config.Password, salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (app *App) verifyEncryption(originalPath, encryptedPath string) error {
	original, err := os.ReadFile(originalPath)
	if err != nil {
		return err
	}

	decrypted, err := app.decryptFile(encryptedPath)
	if err != nil {
		return err
	}

	if !bytes.Equal(original, decrypted) {
		return fmt.Errorf("decrypted content doesn't match original")
	}

	return nil
}
