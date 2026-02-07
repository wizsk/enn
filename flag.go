package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type Option struct {
	Flag string
	Arg  string
	Desc string
}

type Styler struct {
	B  func(a ...any) string
	BU func(a ...any) string
	RB func(a ...any) string
}

func coloredStyler() Styler {
	return Styler{
		B:  color.New(color.Bold).Sprint,
		BU: color.New(color.Bold, color.Underline).Sprint,
		RB: color.New(color.FgRed, color.Bold).Sprint,
	}
}

func plainStyler() Styler {
	id := func(a ...any) string { return fmt.Sprint(a...) }
	return Styler{B: id, BU: id, RB: id}
}

var options = [...]Option{
	{"--conf-dir", "<path>", "Specify config dir (default: ~/.config/" + configFileName + ")"},
	{"--edit-conf", "", "Edit configurations (eg. notes directory path and more)"},
	{"--force-enc", "", "Encrypt all notes even if already encrypted"},
	{"--dec-all", "", "Decrypt all encrypted notes"},
	{"--check-dec", "", "Decrypt new or modified encrypted notes"},
	{"--dec", "<path>", "Decrypt a specific file"},
	{"--out", "<path>", "Output file for --dec flag"},
	{"--check-pass", "", "Test whether you remember the password"},
	{"--change-pass", "", "Change password"},
	{"--no-color", "", "Disable colored output"},
	{"--clean", "", "Cleanup deleted notes"},
	{"--ep", "", "Encypt then git push. Same as running " + progName + " and " + progName + " --push"},
	{"--push", "", "git push"},
	{"--pull", "", "git pull and decrypt new or modified notes"},
	{"--status", "", "Print status"},
	{"--version", "", "Print version"},
	{"--help", "", "Get help message"},
}

func _optionsTxt() string {
	b := color.New(color.Bold)
	bu := color.New(color.Bold, color.Underline)
	rb := color.New(color.FgRed, color.Bold)
	return `A program to keep your ` + rb.Sprint("thoughts") + ` safe
` + bu.Sprint("Usage:") + " " + b.Sprint(progName) + ` [OPTIONS]

` + bu.Sprint("Options:") + `
  ` + b.Sprint("--conf-dir") + ` <path>
      Specify config dir (default: ~/.config/` + configFileName + `)
  ` + b.Sprint("--edit-conf") + `
      Edit configurations (eg. notes directory path and more)
  ` + b.Sprint("--force-enc") + `
      Enecrypt all notes even if the note is already encryped
  ` + b.Sprint("--dec-all") + `
      Decrypt all encrypted notes
  ` + b.Sprint("--check-dec") + `
      Decrypt new or modified encrypted notes
  ` + b.Sprint("--dec") + ` <path>
      Decrypt a specific file
  ` + b.Sprint("--out") + ` <path>
      Output file for ` + b.Sprint("--dec") + ` flag
  ` + b.Sprint("--check-pass") + `
      test yourself if you remember the password or not
  ` + b.Sprint("--change-pass") + `
      change password
  ` + b.Sprint("--no-color") + `
      Disable colored output
  ` + b.Sprint("--clean") + `
      Cleanup deleted notes
  ` + b.Sprint("--push") + `
      git push
  ` + b.Sprint("--pull") + `
      git pull and decrypt new or modified notes`
}

func optionsTxt(st Styler) string {
	var sb strings.Builder

	sb.WriteString("A program to keep your ")
	sb.WriteString(st.RB("thoughts"))
	sb.WriteString(" safe\n\n")

	sb.WriteString(st.BU("Usage:") + " " + st.B(progName) + " [OPTIONS]\n\n")
	sb.WriteString(st.BU("Options:\n"))

	for _, o := range options {
		sb.WriteString("  ")
		sb.WriteString(st.B(o.Flag))
		if o.Arg != "" {
			sb.WriteString(" ")
			sb.WriteString(o.Arg)
		}
		sb.WriteString("\n      ")
		sb.WriteString(o.Desc)
		sb.WriteString("\n")
	}

	return sb.String()
}
