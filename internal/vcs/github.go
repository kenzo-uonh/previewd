package vcs

// GitHub webhook event names (X-GitHub-Event). Payload schemas and the
// actions previewd acts on live in internal/validate.
const (
	EventPullRequest = "pull_request"
	EventPing        = "ping"
)
