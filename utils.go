package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func genPassword(confirm bool) ([]byte, error) {
	var password string
	var salt []byte

	// Ask for password
	for {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, fmt.Errorf("genPassword: reading password: %w", err)
		}
		fmt.Println()
		password = strings.TrimSpace(string(passwordBytes))

		// Check password length
		if len(password) < minPasswordLength {
			fmt.Printf("Password must be at least %d characters\n", minPasswordLength)
			continue
		}
		break
	}

	if confirm {
		for {
			// Confirm password
			fmt.Print("Confirm password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("genPassword: reading confirmation password: %w", err)
			}
			fmt.Println()

			// Check if passwords match
			if strings.TrimSpace(string(confirmBytes)) != password {
				fmt.Println("Passwords don't match. Try again.")
				continue
			}
			break
		}
	}

	// Ask for the salt (any arbitrary text)
	for {
		fmt.Print("Salt: ")
		s, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, fmt.Errorf("genPassword: reading salt: %w", err)
		}
		fmt.Println()
		salt = bytes.TrimSpace(s)

		// Check password length
		if len(salt) < minSaltLength {
			fmt.Printf("salt must be at least %d characters\n", minSaltLength)
			continue
		}
		break
	}

	if confirm {
		for {
			fmt.Print("Confirm Salt: ")
			s, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("genPassword: reading salt: %w", err)
			}
			fmt.Println()
			s = bytes.TrimSpace(s)

			// Check password length
			if !bytes.Equal(salt, s) {
				fmt.Println("salts don't match. Try again.")
				continue
			}
			break
		}
	}

	// Argon2 Parameters
	const timeCost = 3    // Number of iterations
	const memoryCost = 64 // Memory in MiB
	const parallelism = 4 // Number of threads
	const keyLength = 64  // Length of the resulting hash

	saltHash := sha256.Sum256(salt)

	// Hash the password with Argon2
	return argon2.Key([]byte(password), saltHash[:], timeCost, memoryCost*1024, parallelism, keyLength),
		nil
}

func (app *App) verifyBackup() error {
	app.log("Verifying backup integrity")

	encFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	if err != nil {
		return err
	}

	if len(encFiles) == 0 {
		app.warning("No encrypted files to verify")
		return nil
	}

	verified := 0
	failed := 0

	maxWorkers := min(runtime.NumCPU()*2, len(encFiles))
	jobs := make(chan string, maxWorkers)

	// do not buffer
	done := make(chan bool)

	for range maxWorkers {
		go func(j <-chan string, res chan<- bool) {
			for encFile := range jobs {
				originalFile := strings.TrimSuffix(encFile, ".enc")

				if _, err := os.Stat(originalFile); err == nil {
					// Original exists, verify match
					if err := app.verifyEncryption(originalFile, encFile); err != nil {
						app.warning(fmt.Sprintf("Verification mismatch: %s", filepath.Base(encFile)))
						res <- false
						continue
					}
				} else {
					// Just verify decryption works
					if _, err := app.decryptFile(encFile); err != nil {
						app.warning(fmt.Sprintf("Cannot decrypt: %s", filepath.Base(encFile)))
						res <- false
						continue
					}
				}

				res <- true
			}
		}(jobs, done)
	}

	go func() {
		for _, encFile := range encFiles {
			jobs <- encFile
		}
		close(jobs)
	}()

	for range encFiles {
		if <-done {
			verified++
		} else {
			failed++
		}
	}

	if failed == 0 {
		app.success(fmt.Sprintf("All %d encrypted files verified successfully", verified))
		return nil
	}

	return fmt.Errorf("%d files failed verification out of %d total", failed, verified+failed)
}

func (app *App) showStatus() {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("  Backup Status")
	fmt.Println("==========================================")
	fmt.Printf("Notes directory: %s\n", app.config.NotesDir)
	fmt.Printf("Config directory: %s\n", app.configDir)

	mdFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	encFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))

	fmt.Printf("Markdown files: %d\n", len(mdFiles))
	fmt.Printf("Encrypted files: %d\n", len(encFiles))

	cmd := exec.Command("git", "rev-list", "--count", "HEAD")
	cmd.Dir = app.config.NotesDir
	output, err := cmd.Output()
	if err == nil {
		fmt.Printf("Total commits: %s", string(output))
	}

	daysSince := time.Since(app.config.LastVerify).Hours() / 24
	fmt.Printf("Last password verification: %.0f days ago\n", daysSince)

	fmt.Println("==========================================")
	fmt.Println()
}

func (app *App) fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

func (app *App) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func (app *App) log(message string) {
	logMsg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	f, err := os.OpenFile(app.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(logMsg)
}

func (app *App) success(message string) {
	color.Green("SUCC: %s", message)
	app.log("SUCCESS: " + message)
}

func (app *App) warning(message string) {
	color.Yellow("WARN: %s", message)
	app.log("WARNING: " + message)
}

func (app *App) info(message string) {
	color.Cyan("INFO: %s", message)
}

func (app *App) errorMsg(message string) {
	color.Red("ERRO: %s", message)
	app.log("ERROR: " + message)
}

type confirmPromtVal uint

const (
	confirmPromtDefaultNone confirmPromtVal = iota
	confirmPromtDefaultYes
	confirmPromtDefaultNo
)

func confirmPromt(msg string, promt confirmPromtVal) bool {
	for {
		reader := bufio.NewScanner(os.Stdin)

		switch promt {
		case confirmPromtDefaultYes:
			fmt.Print(msg, " (Y/n): ")
		case confirmPromtDefaultNo:
			fmt.Print(msg, " (y/N): ")

		case confirmPromtDefaultNone:
			fallthrough
		default:
			fmt.Print(msg, " (y/n): ")
		}

		reader.Scan()
		res := strings.ToLower(reader.Text())

		switch res {
		case "y":
			return true
		case "n":
			return false
		case "":
			switch promt {
			case confirmPromtDefaultYes:
				return true
			case confirmPromtDefaultNo:
				return false
			}

			fallthrough
		default:
			fmt.Println("Invalid input.")
		}
	}
}
