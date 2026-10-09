package info

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	Name = "bandaid"
)

var (
	version   = "dev"
	commit    = ""
	buildDate = ""
	dirtyFlag = ""
)

var (
	builtAt   time.Time
	dirty     bool
	goVersion = runtime.Version()
	platform  = runtime.GOOS + "/" + runtime.GOARCH
)

func init() {
	if t, err := time.Parse(time.RFC3339, buildDate); err == nil {
		builtAt = t
	}
	if b, err := strconv.ParseBool(dirtyFlag); err == nil {
		dirty = b
	}
}

func Version() string { return version }

func Commit() string { return commit }

func BuiltAt() time.Time { return builtAt }

func Dirty() bool { return dirty }

func GoVersion() string { return goVersion }

func Platform() string { return platform }

func String() string {
	head := Name + " " + version
	if commit != "" {
		head += " " + commit
		if dirty {
			head += "-dirty"
		}
	}
	return fmt.Sprintf("%s (%s %s)", head, goVersion, platform)
}

func Header() string {
	if commit != "" {
		return fmt.Sprintf("%s %s (%s)", Name, version, commit)
	}
	return Name + " " + version
}

func UserAgent() string {
	var parts []string
	if commit != "" {
		p := "+" + commit
		if dirty {
			p += ".dirty"
		}
		parts = append(parts, p)
	}
	parts = append(parts, goVersion, platform)
	return fmt.Sprintf("%s/%s (%s)", Name, version, strings.Join(parts, "; "))
}
