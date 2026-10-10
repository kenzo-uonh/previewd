package validate

import (
	"fmt"
	"strconv"
	"strings"
)

// maxApproversLen bounds PREVIEWD_APPROVERS.
const maxApproversLen = 64 << 10

// Approver is one PREVIEWD_APPROVERS entry. ID is the identity: a review or
// a label counts only when its author's account ID matches. Login is kept
// for logs and the audit trail; a renamed account keeps its ID.
type Approver struct {
	Login string
	ID    int64
}

// ParseApprovers parses PREVIEWD_APPROVERS: comma-separated
// owner/repo:login#id entries, the ID mandatory. Any malformed or empty
// entry, or the same account listed twice for a repository, fails the
// whole value: an approver list is never partly applied. An empty value
// means no approver anywhere.
func ParseApprovers(s string) (map[string][]Approver, error) {
	out := map[string][]Approver{}
	if s == "" {
		return out, nil
	}
	if len(s) > maxApproversLen {
		return nil, fmt.Errorf("approvers exceed %d bytes", maxApproversLen)
	}
	for i, entry := range strings.Split(s, ",") {
		repo, who, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("approver entry %d %s: want owner/repo:login#id", i+1, Quote(entry))
		}
		login, idText, ok := strings.Cut(who, "#")
		if !ok {
			return nil, fmt.Errorf("approver entry %d %s: the numeric account ID (#id) is mandatory", i+1, Quote(entry))
		}
		if err := RepoFullName(repo); err != nil {
			return nil, fmt.Errorf("approver entry %d: %w", i+1, err)
		}
		if err := Login(login); err != nil {
			return nil, fmt.Errorf("approver entry %d: %w", i+1, err)
		}
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != idText {
			return nil, fmt.Errorf("approver entry %d: account id %s is not a positive decimal integer", i+1, Quote(idText))
		}
		for _, a := range out[repo] {
			if a.ID == id {
				return nil, fmt.Errorf("approver entry %d: account %d is listed twice for %s", i+1, id, repo)
			}
		}
		out[repo] = append(out[repo], Approver{Login: login, ID: id})
	}
	return out, nil
}
