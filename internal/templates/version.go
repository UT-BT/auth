package templates

import "strings"

var Version string

func IsDevVersion(v string) bool {
	return strings.Contains(v, "dev")
}
