//go:build integration

package github

import (
	"github.com/cli/cli/v2/api"
	"github.com/jlewi/hydros/pkg/util"
	"net/http"
	"testing"
)

// This is an integration test. It will try to merge the PR specified. This is useful for manual development.
// The PR is hardcoded so once the PR is successfully merged you would need to create a new one and then update the
// test.
func Test_merge_pr(t *testing.T) {
	util.SetupLogger("info", true)
	prURL := "https://github.com/jlewi/hydros-hydrated/pull/11"
	repo, number, err := parsePRURL(prURL)
	if err != nil {
		t.Fatalf("Failed to parse URL %v; error %v", prURL, err)
	}

	pr := &api.PullRequest{

		URL:    prURL,
		Number: number,
	}

	manager, err := getTransportManager()
	if err != nil {
		t.Fatalf("Failed to get github transport manager; error %v", err)
	}

	tr, err := manager.Get(repo.RepoOwner(), repo.RepoName())
	if err != nil {
		t.Fatalf("Failed to get github transport manager; error %v", err)
	}

	client := &http.Client{Transport: &AddHeaderTransport{T: tr}}
	opts := &MergeOptions{
		HttpClient: client,
		IO:         nil,
		Repo:       repo,
		PRNumber:   pr.Number,
		//Branch:                  nil,
		//Remotes:                 nil,
		DeleteBranch:            false,
		MergeMethod:             0,
		AutoMergeEnable:         true,
		AuthorEmail:             "",
		Body:                    "",
		BodySet:                 false,
		Subject:                 "",
		IsDeleteBranchIndicated: false,
		CanDeleteLocalBranch:    false,
		MergeStrategyEmpty:      false,
		MatchHeadCommit:         "",
	}

	m, err := NewMergeContext(opts)
	if err != nil {
		t.Fatalf("Failed to create merge context; error %v", err)
	}
	if err := m.MergePR(); err != nil {
		t.Fatalf("Failed to merge the pr; error %v", err)
	}
}