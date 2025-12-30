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
			app.info(fmt.Sprintf("deleting: %s", e))
			if err = os.Remove(e); err != nil {
				return err
			}

			if _, ok := mnf.Files[name]; ok {
				mod = true
				delete(mnf.Files, name)
			}
		}
	}

	if mod {
		app.info("Saving manifest file")
		if err := app.saveManifest(mnf); err != nil {
			return fmt.Errorf("cleanNotes: while saving manifest: %w", err)
		}
	}

	return nil
}
