package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

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

func replaceHomeWithTilda(p string) string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return strings.Replace(p, homeDir, "~", 1)
	}
	return p
}

func (app *App) showStatus() {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("  Backup Status")
	fmt.Println("==========================================")

	notesDir := replaceHomeWithTilda(app.config.NotesDir)
	confDir := replaceHomeWithTilda(app.configDir)

	fmt.Printf("Notes directory: %s\n", notesDir)
	fmt.Printf("Config directory: %s\n", confDir)

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

func (app *App) log(format string, a ...any) {
	frmt := "[" + time.Now().Format(timeFormat) + "] " + format + "\n"
	logMsg := fmt.Sprintf(frmt, a...)

	f, err := os.OpenFile(app.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(logMsg)
}

func (app *App) success(format string, a ...any) {
	color.Green("SUCC: "+format, a...)
	app.log("SUCCESS: "+format, a...)
}

func (app *App) warning(format string, a ...any) {
	color.Yellow("WARN: "+format, a...)
	app.log("WARNING: "+format, a...)
}

func (app *App) info(format string, a ...any) {
	color.Cyan("INFO: "+format, a...)
}

func (app *App) errorMsg(format string, a ...any) {
	color.Red("ERRO: "+format, a...)
	app.log("ERROR: "+format, a...)
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

func getNotesDir() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	var notesDir string
	var err error

	for {
		fmt.Println("Enter the path to your notes directory (use ~ for your home directory and . (dot) for current direcoty):")
		fmt.Print("> ")
		notesDir, err = reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read notes directory: %w", err)
		}
		notesDir = strings.TrimSpace(notesDir)
		if notesDir == "" {
			continue
		}

		// Expand ~ to home directory
		if strings.HasPrefix(notesDir, "~") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				color.Red("failed to get path for '~': %v\n", err)
				continue
			}
			notesDir = filepath.Join(homeDir, notesDir[1:])
		}

		// Convert to absolute path
		notesDir, err = filepath.Abs(notesDir)
		if err != nil {
			color.Red("failed to get absolute path: %s\n", err)
			continue
		}

		// Verify directory exists
		if _, err := os.Stat(notesDir); os.IsNotExist(err) {
			if err = os.Mkdir(notesDir, 0700); err != nil {
				color.Red("directory does not exist and could not create: %s\n", notesDir)
				continue
			}
		}
		break
	}

	return notesDir, nil
}

// ignore error
func ierr[T any](v T, _ error) T {
	return v
}

// ignore value
func ival[T any](_ T, e error) error {
	return e
}

func printVersion() {
	printVersionWritter(os.Stdout)
}

func printVersionWritter(wm io.Writer) {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "%s: %s\n", progName, progVersion)
	if buildTime != "" {
		if u, err := strconv.ParseInt(buildTime, 10, 64); err == nil {
			u := time.Unix(u, 0)
			fmt.Fprintf(w, "compilled at: %s\n", u.Format(time.RFC1123))
		}
	}

	if gitCommit != "" {
		fmt.Fprintf(w, "git commit: %s\n", gitCommit)
	}
	if gitCommitMsg != "" {
		msg, err := base64.StdEncoding.DecodeString(gitCommitMsg)
		if err == nil {
			fmt.Fprintf(w, "git commit message: %s\n", msg)
		}
	}
	wm.Write(w.Bytes())
}
