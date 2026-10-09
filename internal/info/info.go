package info

import "fmt"

const (
	Name = ""
)

var (
	BuildDate  string = "1970-01-01 00:00:00+00:00"
	CommitHash string = "0000000000000000000000000000000000000000"
	Version    string = "N/A"
	Platform   string = "N/A"
	GoVersion  string = "N/A"
)

var (
	str string
)

func init() {
	str = fmt.Sprintf(
		"%s %s %s (%s %s)",
		Name,
		Version,
		firstN(CommitHash, 7),
		GoVersion,
		Platform,
	)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func String() string {
	return str
}
