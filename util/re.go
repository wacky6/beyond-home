package util

import "regexp"

var RE_SPLIT_SPACES = regexp.MustCompile(`\s`)
var RE_SPLIT_NEWLINE = regexp.MustCompile(`\r\n|\r|\n|\x0085|\x2028|\x2029`)
