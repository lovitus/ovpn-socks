// Package engineargs tokenizes editable command arguments without invoking a shell.
package engineargs

import (
	"errors"
	"strings"
	"unicode"
)

// Split accepts shell-style single/double quoting and escaped whitespace. It
// deliberately performs no variable expansion, command substitution, globbing,
// redirection or pipelines. Newlines separate arguments; backslash-newline joins
// a continued line. Windows path separators remain literal unless escaping a
// quote, whitespace or another backslash.
func Split(text string) ([]string, error) {
	if len(text) > 128*1024 {
		return nil, errors.New("命令行参数超过 128 KiB")
	}
	var out []string
	var token strings.Builder
	var quote rune
	started := false
	runes := []rune(text)
	flush := func() {
		if started {
			out = append(out, token.String())
			token.Reset()
			started = false
		}
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == 0 {
			return nil, errors.New("命令行参数不能包含 NUL")
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				token.WriteRune(c)
			}
			continue
		}
		if c == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			if next == '\n' {
				i++
				continue
			}
			if next == '\r' && i+2 < len(runes) && runes[i+2] == '\n' {
				i += 2
				continue
			}
			if next == '\\' || next == '"' || (quote == 0 && (next == '\'' || unicode.IsSpace(next))) {
				token.WriteRune(next)
				started = true
				i++
				continue
			}
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				token.WriteRune(c)
			}
			continue
		}
		switch {
		case c == '\'' || c == '"':
			quote = c
			started = true
		case unicode.IsSpace(c):
			flush()
		case c == '|' || c == '&' || c == ';' || c == '<' || c == '>':
			return nil, errors.New("请输入程序参数，不支持 shell 管道、重定向或多条命令；URL 中这些字符请放在引号内")
		default:
			token.WriteRune(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, errors.New("命令行参数中的引号没有闭合")
	}
	flush()
	if len(out) > 1024 {
		return nil, errors.New("命令行参数最多 1024 个")
	}
	return out, nil
}
