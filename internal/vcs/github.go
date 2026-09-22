package vcs

// WebhookEvent represents incoming GitHub webhook payload headers.
const (
	EventPullRequest = "pull_request"
	EventPing        = "ping"

	ActionOpened      = "opened"
	ActionReopened    = "reopened"
	ActionSynchronize = "synchronize"
	ActionClosed      = "closed"
)

// PullRequestPayload models the minimal GitHub webhook JSON schema required for EaaS lifecycle orchestration.
type PullRequestPayload struct {
	Action      string             `json:"action"`
	Number      int                `json:"number"`
	PullRequest PullRequestDetails `json:"pull_request"`
	Repository  RepositoryDetails  `json:"repository"`
}

// PullRequestDetails captures branch ref and commit SHA metadata.
type PullRequestDetails struct {
	Head CommitRef `json:"head"`
	Base CommitRef `json:"base"`
}

// CommitRef identifies git branch references and commit hashes.
type CommitRef struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// RepositoryDetails isolates git origin data.
type RepositoryDetails struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
}
