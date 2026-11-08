package acquire

import (
	"net/url"
	"strings"
)

// GitHubCommitQuery is the only query-bearing initial download URL accepted by
// the bulk fetcher. It identifies one repository, file and single-component ref;
// it permits neither credentials nor arbitrary API requests or pagination.
type GitHubCommitQuery struct{ Owner, Repository, Ref, Path string }

func ParseGitHubCommitURL(raw string) (GitHubCommitQuery, bool) {
	var result GitHubCommitQuery
	if len(raw) == 0 || len(raw) > 4096 {
		return result, false
	}
	for _, c := range raw {
		if c <= 32 || c >= 127 || c == '\\' || c == '#' {
			return result, false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "api.github.com" || u.User != nil || u.RawPath != "" || u.Fragment != "" {
		return result, false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "repos" || parts[4] != "commits" {
		return result, false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 3 || len(query["path"]) != 1 || len(query["sha"]) != 1 || len(query["per_page"]) != 1 || query.Get("per_page") != "1" {
		return result, false
	}
	result = GitHubCommitQuery{parts[2], parts[3], query.Get("sha"), query.Get("path")}
	if !commitAtom(result.Owner) || !commitAtom(result.Repository) || !commitAtom(result.Ref) || len(result.Path) > 1024 {
		return GitHubCommitQuery{}, false
	}
	segments := strings.Split(result.Path, "/")
	if len(segments) > 32 {
		return GitHubCommitQuery{}, false
	}
	for _, segment := range segments {
		if !commitAtom(segment) {
			return GitHubCommitQuery{}, false
		}
	}
	return result, true
}

func commitAtom(value string) bool {
	if len(value) == 0 || len(value) > 255 || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
