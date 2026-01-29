package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	fileMagic = "NENC"
	fileVer   = byte(1)

	appSalt = "enn-encryption-v1"
)

// if manifest is new then all the notes are naturally forcefully encryped
// btw, manifest is never modified
func (app *App) encryptNotes(manifest FileManifest) (FileManifest, error) {
	newMenifest := FileManifest{}
	app.log("Starting encryption process")

	mdFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	if err != nil {
		return newMenifest, err
	}

	if len(mdFiles) == 0 {
		app.warning("No .md files found")
		return newMenifest, nil
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
					continue
				}

				// Calculate hash
				hash, err := app.fileHash(mdFile)
				if err != nil {
					res <- result{err: fmt.Errorf("failed to hash %s: %w", filename, err)}
					continue
				}

				// Check if encryption is needed
				if oldInfo, exists := manifest.Files[filename]; exists {
					if oldInfo.Hash == hash {
						if _, err = os.Stat(encryptedFile); err == nil {
							res <- result{suc: false, fn: filename, fi: oldInfo}
							continue
						}
					}
				} else if _, err = os.Stat(encryptedFile); err == nil {
					if data, _ := app.decryptFile(encryptedFile); len(data) > 0 {
						encHash := fmt.Sprintf("%x", sha256.Sum256(data))
						if hash == encHash {
							res <- result{suc: false, fn: filename,
								fi: FileInfo{
									Hash:         hash,
									LastModified: fileInfo.ModTime(),
								}}
							continue
						}
					}
				}

				app.info(fmt.Sprintf("Encrypting: %s", filename))

				// Backup existing encrypted file
				backupFile := encryptedFile + ".backup"
				if _, err := os.Stat(encryptedFile); err == nil {
					if err := os.Rename(encryptedFile, backupFile); err != nil {
						res <- result{err: fmt.Errorf("failed to backup %s: %w", filename, err)}
						continue
					}
				}

				// Encrypt file
				encData, err := app.encryptFile(mdFile)
				if err != nil {
					res <- result{err: fmt.Errorf("failed to encrypt %s: %w", filename, err)}
					continue
				}

				if err = os.WriteFile(encryptedFile, encData, 0600); err != nil {
					os.Remove(encryptedFile)
					if _, err := os.Stat(backupFile); err == nil {
						os.Rename(backupFile, encryptedFile)
					}
					res <- result{suc: false, err: fmt.Errorf("failed to write %s: %w", filename, err)}
					continue
				}

				// Verify encryption
				if err := app.verifyEncryption(mdFile, encryptedFile); err != nil {
					os.Remove(encryptedFile)
					if _, err := os.Stat(backupFile); err == nil {
						os.Rename(backupFile, encryptedFile)
					}
					res <- result{suc: false, err: fmt.Errorf("verification failed for %s: %w", filename, err)}
					continue
				}

				// Success - remove backup
				os.Remove(backupFile)

				app.success(fmt.Sprintf("Encrypted and verified: %s", filename))

				fi := FileInfo{
					Hash:         hash,
					LastModified: fileInfo.ModTime(),
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
	newMenifest.Files = make(map[string]FileInfo, len(mdFiles))
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

func (app *App) decryptAllMode() error {
	fmt.Println("==========================================")
	fmt.Println("  Decrypt All Notes")
	fmt.Println("==========================================")
	fmt.Println()

	app.log("Starting decrypt-all process")

	encFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	if err != nil {
		return err
	}

	if len(encFiles) == 0 {
		app.warning("No .enc files found to decrypt")
		return nil
	}

	mdFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	mdMap := make(map[string]struct{}, len(mdFiles))
	if len(mdFiles) > 0 {
		// mdMap := enc_md_map(mdFiles)
		for _, v := range mdFiles {
			v = filepath.Base(v)
			mdMap[v] = struct{}{}
		}

		// a, b
		// -1 -> a b	a comes before b
		// 1  -> b a	b comes before a
		// 0  -> a b	no swap
		slices.SortFunc(encFiles, func(a, b string) int {
			aBase := filepath.Base(a)
			aName := strings.TrimSuffix(aBase, ".enc") // foo.md

			bBase := filepath.Base(b)
			bName := strings.TrimSuffix(bBase, ".enc") // foo.md

			_, aOk := mdMap[aName]
			_, bOk := mdMap[bName]

			if aOk && bOk {
				return 0
			} else if aOk {
				return 1
			} else {
				return -1
			}
		})
	}

	app.info(fmt.Sprintf("Found %d encrypted files", len(encFiles)))
	fmt.Println()

	successCount := 0
	failCount := 0

	warnedAboutExistingMdFiles := false
	promtBeforeOverwrite := true
loop:
	for i, encFile := range encFiles {
		filename := filepath.Base(encFile)
		outputFile := strings.TrimSuffix(encFile, ".enc")

		// Check if output file already exists
		if _, ok := mdMap[strings.TrimSuffix(filename, ".enc")]; ok {
			if !warnedAboutExistingMdFiles {
				warnedAboutExistingMdFiles = true
				app.warning("The following files are already decrypted")
				for _, encF := range encFiles[i:] {
					f := filepath.Base(encF)
					app.log(f)
					fmt.Println(f)
				}

				sc := bufio.NewScanner(os.Stdin)

			promtLoop:
				for {
					fmt.Println()
					fmt.Println("How do you intend to proceed?")
					fmt.Println("1. Skip and exit")
					fmt.Println("2. Select and overwrite")
					fmt.Println("3. Overwrite all")
					fmt.Print("[1-3] > ")

					b := byte('0')
					if sc.Scan() && len(sc.Bytes()) == 1 {
						b = sc.Bytes()[0]
					}
					switch b {
					case '1':
						break loop
					case '2':
						break promtLoop
					case '3':
						if confirmPromt("Do you really want to overwrite all of them?", confirmPromtDefaultNo) {
							promtBeforeOverwrite = false
							break promtLoop
						}
						break loop

					default:
						fmt.Println("invalid choice")
					}
				}
			}

			if promtBeforeOverwrite {
				app.warning(fmt.Sprintf("Unencrypted file already exists for: %s", filename))
				if !confirmPromt("Do you want to overwrite it?", confirmPromtDefaultNo) {
					continue
				}
			}

		}

		app.info(fmt.Sprintf("Decrypting: %s", filename))

		// Decrypt
		plaintext, err := app.decryptFile(encFile)
		if err != nil {
			app.errorMsg(fmt.Sprintf("Failed to decrypt %s: %v", filename, err))
			failCount++
			continue
		}

		// Write decrypted file
		if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
			app.errorMsg(fmt.Sprintf("Failed to write %s: %v", filepath.Base(outputFile), err))
			failCount++
			continue
		}

		app.success(fmt.Sprintf("Decrypted: %s → %s", filename, filepath.Base(outputFile)))
		successCount++
	}

	fmt.Println()
	if failCount > 0 {
		app.warning(fmt.Sprintf("Decrypted %d files, %d failed", successCount, failCount))
	} else if successCount > 0 {
		app.success(fmt.Sprintf("Successfully decrypted all %d file[s]!", successCount))
	}

	app.log(fmt.Sprintf("Decrypt-all completed: %d success[es], %d fail[s]", successCount, failCount))

	return nil
}

func (app *App) decryptMode(encryptedPath, outputPath string) error {
	// Check if file exists
	if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", encryptedPath)
	}

	app.info(fmt.Sprintf("Decrypting: %s", replaceHomeWithTilda(encryptedPath)))

	// Decrypt file
	plaintext, err := app.decryptFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Write output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		app.success(fmt.Sprintf("Decrypted to: %s", replaceHomeWithTilda(outputPath)))
	} else {
		// Write to stdout
		os.Stdout.Write(plaintext)
	}

	return nil
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
