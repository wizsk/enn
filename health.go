package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (app *App) cleanNotes() error {
	mdFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	if err != nil {
		return fmt.Errorf("checkNotes: %w", err)
	}

	encFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	if err != nil {
		return fmt.Errorf("checkNotes: %w", err)
	}

	// mdMap := enc_md_map(mdFiles)
	mdMap := make(map[string]struct{}, len(mdFiles))
	for _, v := range mdFiles {
		v = filepath.Base(v)
		mdMap[v] = struct{}{}
	}

	mnf, err := app.loadManifest()
	if err != nil {
		return fmt.Errorf("cleanNotes: while loading manifest: %w", err)
	}

	mod := false
	for _, e := range encFiles {
		base := filepath.Base(e)
		name := strings.TrimSuffix(base, ".enc") // foo.md

		if _, ok := mdMap[name]; !ok && confirmPromt(fmt.Sprintf("Delete: %s", base), confirmPromtDefaultNo) {
			mod = true
			app.info(fmt.Sprintf("deleting: %s", e))
			if err = os.Remove(e); err != nil {
				return err
			}
			delete(mnf.Files, name)
		}
	}

	if mod {
		app.info("Saving manifest file")
		if err := app.saveManifest(mnf); err != nil {
			return fmt.Errorf("cleanNotes: while saving manifest: %w", err)
		}
		return app.gitCommit("afeter cleaing", mnf)
	}
	return nil
}

func (app *App) checkAndDecNotes() error {
	manifest, err := app.loadManifest()
	if err != nil {
		if os.IsNotExist(err) {
			app.warning("No manifest file found")
			return nil
		}
		return err
	}

	var (
		mdPath, hash string
		stat         os.FileInfo
		successCount = 0
		skippedCount = 0
	)

	for md, info := range manifest.Files {
		mdPath = filepath.Join(app.config.NotesDir, md)
		stat, err = os.Stat(mdPath)
		if os.IsNotExist(err) {
			// file maybe deleted? or a new file
			app.info(fmt.Sprintf("Seems like %q is a new note", md))
			goto dec
		}

		hash, err = app.fileHash(mdPath)
		if err != nil {
			return err
		}

		// if hash is the same then skip
		if hash == info.Hash {
			continue
		}

		// this means the file which was pulled is newer so, decrypt and
		// put inplace of the old file
		if info.LastModified.Unix() != stat.ModTime().Unix() {
			app.warning(fmt.Sprintf("%q was modified in this device [%s] and in the backup [%s]",
				md, stat.ModTime().Format(timeFormat), stat.ModTime().Format(timeFormat)))
		}
		// goto dec
	dec:
		p := fmt.Sprintf("Do you want to decrypt '%s.enc' to '%s'?", md, md)
		if !confirmPromt(p, confirmPromtDefaultYes) {
			app.info(fmt.Sprintf("Skipping: %q", md))
			skippedCount++
			continue
		}
		if err := app.decryptMode(mdPath+".enc", mdPath); err != nil {
			return err
		}
		app.success(fmt.Sprintf("%q decrypted successfully", md))
		successCount++
	}

	if successCount > 0 || skippedCount > 0 {
		app.success(fmt.Sprintf("Encryption summary: %d deccrypted, %d skipped", successCount, skippedCount))
	}
	return err
}
