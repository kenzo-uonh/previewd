package vcs

// GitHub webhook event names (X-GitHub-Event). Payload schemas and the
// actions previewd acts on live in internal/validate.
const (
	EventPullRequest       = "pull_request"
	EventPullRequestReview = "pull_request_review"
	EventPing              = "ping"
)

// PRState is a pull request as GHES reports it at the time of the call: the
// truth an approval or a revocation is judged against (V1 spec 3.4). The
// GHES client that fills it is phase C3.
type PRState struct {
	Open        bool
	HeadSHA     string
	HeadRepo    string // "" when the head repository (a fork) was deleted
	OpenerLogin string
}

// WriteAccess reports whether a repository permission, as GHES names it,
// includes write: admin, maintain or write. Anything else, unknown names
// included, does not.
func WriteAccess(permission string) bool {
	switch permission {
	case "admin", "maintain", "write":
		return true
	}
	return false
}

// Trusted is the trust rule (V1 spec D4, D-V1-5): the head lives in the
// base repository and its opener has write access there. A deleted head
// repository is untrusted.
func Trusted(pr PRState, repo, openerPermission string) bool {
	return pr.HeadRepo != "" && pr.HeadRepo == repo && WriteAccess(openerPermission)
}
