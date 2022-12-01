package github

// Code to merge PRs.
// It is based on GitHub's CLI code.
// https://github.com/cli/cli/blob/trunk/pkg/cmd/pr/merge/merge.go

import (
	"fmt"
	"github.com/cli/cli/v2/api"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jlewi/hydros/pkg/github/ghrepo"
	"github.com/pkg/errors"
	"github.com/shurcooL/githubv4"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// TODO(jeremy): Can we just use githubv4.PullRequestMergeMethod
type PullRequestMergeMethod int

const (
	PullRequestMergeMethodMerge PullRequestMergeMethod = iota
	PullRequestMergeMethodRebase
	PullRequestMergeMethodSquash
)

const (
	MergeStateStatusBehind   = "BEHIND"
	MergeStateStatusBlocked  = "BLOCKED"
	MergeStateStatusClosed   = "CLOSED"
	MergeStateStatusClean    = "CLEAN"
	MergeStateStatusDirty    = "DIRTY"
	MergeStateStatusHasHooks = "HAS_HOOKS"
	MergeStateStatusMerged   = "MERGED"
	MergeStateStatusUnstable = "UNSTABLE"
)

// MergeOptions are the options used to construct a context.
type MergeOptions struct {
	HttpClient *http.Client
	// The number for the PR
	PRNumber int
	Repo     ghrepo.Interface

	MergeMethod PullRequestMergeMethod

	AutoMergeEnable         bool
	IsDeleteBranchIndicated bool
	CanDeleteLocalBranch    bool
	MergeStrategyEmpty      bool
	MatchHeadCommit         string
}

// ErrAlreadyInMergeQueue indicates that the pull request is already in a merge queue
var ErrAlreadyInMergeQueue = errors.New("already in merge queue")

// MergeContext contains state and dependencies to merge a pull request.
//
// It is oppinionated about how merges should be done
// i) If a PR can't be merged e.g. because of status checks then it will enable autoMerge so it will be merged as soon
//
//	as possible
//
// ii) It uses squash method to do the merge to preserve linear history.
type MergeContext struct {
	pr       *api.PullRequest
	baseRepo ghrepo.Interface
	opts     *MergeOptions
	log      logr.Logger
}

// Check if this pull request is in a merge queue
func (m *MergeContext) inMergeQueue() error {
	log := zapr.NewLogger(zap.L())
	// if the pull request is in a merge queue no further action is possible
	if m.pr.IsInMergeQueue {
		log.Info("Pull request already in merge queue", "number", m.pr.Number)
		return ErrAlreadyInMergeQueue
	}
	return nil
}

// Merge the pull request.
func (m *MergeContext) merge() error {
	log := zapr.NewLogger(zap.L())

	payload := mergePayload{
		repo:          m.baseRepo,
		pullRequestID: m.pr.ID,
		// N.B. We are oppionated and use squash merge to give linear history.
		method: PullRequestMergeMethodSquash,
		// Automatically enable automerge if there is a queue
		auto:            true,
		expectedHeadOid: m.opts.MatchHeadCommit,
	}

	if m.shouldAddToMergeQueue() {
		if !m.opts.MergeStrategyEmpty {
			// only warn for now
			log.Info("The merge strategy will be set by the merge queue", "baseRef", m.pr.BaseRefName)

		}
		// auto merge will either enable auto merge or add to the merge queue
		payload.auto = true
	}

	err := mergePullRequest(m.opts.HttpClient, payload)
	if err != nil {
		return err
	}

	if m.shouldAddToMergeQueue() {
		log.Info("Pull request will be added to the merge queue when ready", "number", m.pr.Number, "baseRef", m.pr.BaseRefName)
		return nil
	}

	if payload.auto {
		method := ""
		switch payload.method {
		case PullRequestMergeMethodRebase:
			method = " via rebase"
		case PullRequestMergeMethodSquash:
			method = " via squash"
		}
		log.Info("Pull request will be automatically merged when all requirements are met", "prNumber", m.pr.Number, "method", method)
		return nil
	}

	action := "Merged"
	switch payload.method {
	case PullRequestMergeMethodRebase:
		action = "Rebased and merged"
	case PullRequestMergeMethodSquash:
		action = "Squashed and merged"
	}
	log.Info("pull request was merged", "method", action, "prNumber", m.pr.Number, "title", m.pr.Title)
	return nil
}

// TODO(jeremy): I think we can drop this; there should be no reason to delete local branches.
// Delete local branch if requested and if allowed.
//func (m *MergeContext) deleteLocalBranch() error {
//	if m.crossRepoPR || m.autoMerge {
//		return nil
//	}
//
//	if m.merged {
//		// prompt for delete
//		if m.opts.IO.CanPrompt() && !m.opts.IsDeleteBranchIndicated {
//			//nolint:staticcheck // SA1019: prompt.SurveyAskOne is deprecated: use Prompter
//			err := prompt.SurveyAskOne(&survey.Confirm{
//				Message: fmt.Sprintf("Pull request #%d was already merged. Delete the branch locally?", m.pr.Number),
//				Default: false,
//			}, &m.deleteBranch)
//			if err != nil {
//				return fmt.Errorf("could not prompt: %w", err)
//			}
//		} else {
//			_ = m.warnf(fmt.Sprintf("%s Pull request #%d was already merged\n", m.cs.WarningIcon(), m.pr.Number))
//		}
//	}
//
//	if !m.deleteBranch || !m.opts.CanDeleteLocalBranch || !m.localBranchExists {
//		return nil
//	}
//
//	currentBranch, err := m.opts.Branch()
//	if err != nil {
//		return err
//	}
//
//	ctx := context.Background()
//
//	// branch the command was run on is the same as the pull request branch
//	if currentBranch == m.pr.HeadRefName {
//		remotes, err := m.opts.Remotes()
//		if err != nil {
//			return err
//		}
//
//		baseRemote, err := remotes.FindByRepo(m.baseRepo.RepoOwner(), m.baseRepo.RepoName())
//		if err != nil {
//			return err
//		}
//
//		targetBranch := m.pr.BaseRefName
//		if m.opts.GitClient.HasLocalBranch(ctx, targetBranch) {
//			if err := m.opts.GitClient.CheckoutBranch(ctx, targetBranch); err != nil {
//				return err
//			}
//		} else {
//			if err := m.opts.GitClient.CheckoutNewBranch(ctx, baseRemote.Name, targetBranch); err != nil {
//				return err
//			}
//		}
//
//		if err := m.opts.GitClient.Pull(ctx, baseRemote.Name, targetBranch); err != nil {
//			_ = m.warnf(fmt.Sprintf("%s warning: not possible to fast-forward to: %q\n", m.cs.WarningIcon(), targetBranch))
//		}
//
//		m.switchedToBranch = targetBranch
//	}
//
//	if err := m.opts.GitClient.DeleteLocalBranch(ctx, m.pr.HeadRefName); err != nil {
//		return fmt.Errorf("failed to delete local branch %s: %w", m.cs.Cyan(m.pr.HeadRefName), err)
//	}
//
//	return nil
//}

// TODO(jeremy): I think we can drop this; can we let this be enforced at the repository level?
// Delete the remote branch if requested and if allowed.
//func (m *MergeContext) deleteRemoteBranch() error {
//	// the user was already asked if they want to delete the branch if they didn't provide the flag
//	if !m.deleteBranch || m.crossRepoPR || m.autoMerge {
//		return nil
//	}
//
//	if !m.merged {
//		apiClient := api.NewClientFromHTTP(m.httpClient)
//		err := api.BranchDeleteRemote(apiClient, m.baseRepo, m.pr.HeadRefName)
//		var httpErr api.HTTPError
//		// The ref might have already been deleted by GitHub
//		if err != nil && (!errors.As(err, &httpErr) || httpErr.StatusCode != 422) {
//			return fmt.Errorf("failed to delete remote branch %s: %w", m.cs.Cyan(m.pr.HeadRefName), err)
//		}
//	}
//
//	branch := ""
//	if m.switchedToBranch != "" {
//		branch = fmt.Sprintf(" and switched to branch %s", m.cs.Cyan(m.switchedToBranch))
//	}
//	return m.infof("%s Deleted branch %s%s\n", m.cs.SuccessIconWithColor(m.cs.Red), m.cs.Cyan(m.pr.HeadRefName), branch)
//}

// Add the Pull Request to a merge queue
func (m *MergeContext) shouldAddToMergeQueue() bool {
	return m.pr.IsMergeQueueEnabled
}

// NewMergeContext creates a new MergeContext.
// This will locate the PR and get its current status.
func NewMergeContext(opts *MergeOptions) (*MergeContext, error) {
	//if opts.Finder == nil {
	//	return nil, errors.New("Finder can't be nil")
	//}
	//findOptions := shared.FindOptions{
	//	Selector: opts.SelectorArg,
	//	Fields:   []string{"id", "number", "state", "title", "lastCommit", "mergeStateStatus", "headRepositoryOwner", "headRefName", "baseRefName", "headRefOid", "isInMergeQueue", "isMergeQueueEnabled"},
	//}
	if opts.Repo == nil {
		return nil, errors.New("repo is required")
	}
	if opts.PRNumber == 0 {
		return nil, errors.New("PR number is required")
	}

	// N.B github/cli/cli was also fetching the fields "isInMergeQueue", "isMergeQueueEnabled" but when I tried
	// I was getting an error those fields don't exist. I think that might be a preview feature and access to those
	// fields might be restricted.
	fields := []string{"id", "number", "state", "title", "lastCommit", "mergeStateStatus", "headRepositoryOwner", "headRefName", "baseRefName", "headRefOid"}
	pr, err := fetchPR(opts.HttpClient, opts.Repo, opts.PRNumber, fields)
	//pr, baseRepo, err := opts.Finder.Find(findOptions)
	if err != nil {
		return nil, err
	}

	log := zapr.NewLogger(zap.L()).WithValues("prNumber", pr.Number)
	return &MergeContext{
		opts:     opts,
		pr:       pr,
		log:      log,
		baseRepo: opts.Repo,
		//merged:             pr.State == MergeStateStatusMerged,
		//mergeQueueRequired: pr.IsMergeQueueEnabled,
	}, nil
}

// MergePR merges a PR
func (m *MergeContext) MergePR() error {
	log := m.log
	pr := m.pr
	if pr.State == MergeStateStatusClosed {
		log.Info("PR can't be merged it has been closed")
		return errors.Errorf("Can't merge PR %v it has been closed", pr.URL)
	}
	if pr.State == MergeStateStatusMerged {
		log.Info("PR has already been merged")
		return nil
	}
	if err := m.inMergeQueue(); err != nil {
		log.Info("PR is already in merge queue")
		return nil
	}

	if isImmediatelyMergeable(m.pr.MergeStateStatus) {
		log.Info("PR is immediately mergeable")
	}

	if pr.IsMergeQueueEnabled {
		log.Info("PR will be added to merge queue")
	}

	if reason, blocked := blockedReason(m.pr.MergeStateStatus); blocked {
		log.Info("PR merging is blocked", "reason", reason)
		return errors.Errorf("PR merging is blocked; MergeStateStatus: %v reason: %v", m.pr.MergeStateStatus, reason)
	}

	if err := m.merge(); err != nil {
		return err
	}

	// TODO(jeremy): This shouldn't be a code path we need to support.
	//if err := ctx.deleteLocalBranch(); err != nil {
	//	return err
	//}
	//
	//if err := ctx.deleteRemoteBranch(); err != nil {
	//	return err
	//}

	return nil
}

// TODO(jeremy): We shouldn't need to prompt for merge method. We should be oppinionated.
//func mergeMethodSurvey(baseRepo *api.Repository) (PullRequestMergeMethod, error) {
//	type mergeOption struct {
//		title  string
//		method PullRequestMergeMethod
//	}
//
//	var mergeOpts []mergeOption
//	if baseRepo.MergeCommitAllowed {
//		opt := mergeOption{title: "Create a merge commit", method: PullRequestMergeMethodMerge}
//		mergeOpts = append(mergeOpts, opt)
//	}
//	if baseRepo.RebaseMergeAllowed {
//		opt := mergeOption{title: "Rebase and merge", method: PullRequestMergeMethodRebase}
//		mergeOpts = append(mergeOpts, opt)
//	}
//	if baseRepo.SquashMergeAllowed {
//		opt := mergeOption{title: "Squash and merge", method: PullRequestMergeMethodSquash}
//		mergeOpts = append(mergeOpts, opt)
//	}
//
//	var surveyOpts []string
//	for _, v := range mergeOpts {
//		surveyOpts = append(surveyOpts, v.title)
//	}
//
//	mergeQuestion := &survey.Select{
//		Message: "What merge method would you like to use?",
//		Options: surveyOpts,
//	}
//
//	var result int
//	//nolint:staticcheck // SA1019: prompt.SurveyAskOne is deprecated: use Prompter
//	err := prompt.SurveyAskOne(mergeQuestion, &result)
//	return mergeOpts[result].method, err
//}

// TODO(jeremy): We shouldn't need to prompt for whether to delete a branch.
//func deleteBranchSurvey(opts *MergeOptions, crossRepoPR, localBranchExists bool) (bool, error) {
//	if !crossRepoPR && !opts.IsDeleteBranchIndicated {
//		var message string
//		if opts.CanDeleteLocalBranch && localBranchExists {
//			message = "Delete the branch locally and on GitHub?"
//		} else {
//			message = "Delete the branch on GitHub?"
//		}
//
//		var result bool
//		submit := &survey.Confirm{
//			Message: message,
//			Default: false,
//		}
//		//nolint:staticcheck // SA1019: prompt.SurveyAskOne is deprecated: use Prompter
//		err := prompt.SurveyAskOne(submit, &result)
//		return result, err
//	}
//
//	return opts.DeleteBranch, nil
//}

// TODO(jeremy): We shouldn't need to confirm any input.
//func confirmSurvey(allowEditMsg bool) (shared.Action, error) {
//	const (
//		submitLabel            = "Submit"
//		editCommitSubjectLabel = "Edit commit subject"
//		editCommitMsgLabel     = "Edit commit message"
//		cancelLabel            = "Cancel"
//	)
//
//	options := []string{submitLabel}
//	if allowEditMsg {
//		options = append(options, editCommitSubjectLabel, editCommitMsgLabel)
//	}
//	options = append(options, cancelLabel)
//
//	var result string
//	submit := &survey.Select{
//		Message: "What's next?",
//		Options: options,
//	}
//	//nolint:staticcheck // SA1019: prompt.SurveyAskOne is deprecated: use Prompter
//	err := prompt.SurveyAskOne(submit, &result)
//	if err != nil {
//		return shared.CancelAction, fmt.Errorf("could not prompt: %w", err)
//	}
//
//	switch result {
//	case submitLabel:
//		return shared.SubmitAction, nil
//	case editCommitSubjectLabel:
//		return shared.EditCommitSubjectAction, nil
//	case editCommitMsgLabel:
//		return shared.EditCommitMessageAction, nil
//	default:
//		return shared.CancelAction, nil
//	}
//}

// TODO(jeremy): Don't think we need this either.
//func confirmSubmission(client *http.Client, opts *MergeOptions, action shared.Action, payload *mergePayload) (bool, error) {
//	var err error
//
//	switch action {
//	case shared.EditCommitMessageAction:
//		if !payload.setCommitBody {
//			_, payload.commitBody, err = getMergeText(client, payload.repo, payload.pullRequestID, payload.method)
//			if err != nil {
//				return false, err
//			}
//		}
//
//		payload.commitBody, err = opts.Editor.Edit("*.md", payload.commitBody)
//		if err != nil {
//			return false, err
//		}
//		payload.setCommitBody = true
//
//		return false, nil
//
//	case shared.EditCommitSubjectAction:
//		if payload.commitSubject == "" {
//			payload.commitSubject, _, err = getMergeText(client, payload.repo, payload.pullRequestID, payload.method)
//			if err != nil {
//				return false, err
//			}
//		}
//
//		payload.commitSubject, err = opts.Editor.Edit("*.md", payload.commitSubject)
//		if err != nil {
//			return false, err
//		}
//
//		return false, nil
//
//	case shared.CancelAction:
//		fmt.Fprintln(opts.IO.ErrOut, "Cancelled.")
//		return false, cmdutil.CancelError
//
//	case shared.SubmitAction:
//		return true, nil
//
//	default:
//		return false, fmt.Errorf("unable to confirm: %w", err)
//	}
//}

// Shouldn't need an editor
//type userEditor struct {
//	io     *iostreams.IOStreams
//	config func() (config.Config, error)
//}
//
//func (e *userEditor) Edit(filename, startingText string) (string, error) {
//	editorCommand, err := cmdutil.DetermineEditor(e.config)
//	if err != nil {
//		return "", err
//	}
//
//	return surveyext.Edit(editorCommand, filename, startingText, e.io.In, e.io.Out, e.io.ErrOut)
//}

// blockedReason translates various MergeStateStatus GraphQL values into human-readable reason
// The bool indicates whether merging is blocked
func blockedReason(status string) (string, bool) {
	switch status {
	case MergeStateStatusBlocked:
		return "the base branch policy prohibits the merge", true
	case MergeStateStatusBehind:
		return "the head branch is not up to date with the base branch", true
	case MergeStateStatusDirty:
		return "the merge commit cannot be cleanly created", true
	default:
		return "", false
	}
}

func allowsAdminOverride(status string) bool {
	switch status {
	case MergeStateStatusBlocked, MergeStateStatusBehind:
		return true
	default:
		return false
	}
}

//func remoteForMergeConflictResolution(baseRepo ghrepo.Interface, pr *api.PullRequest, opts *MergeOptions) *ghContext.Remote {
//	if !mergeConflictStatus(pr.MergeStateStatus) || !opts.CanDeleteLocalBranch {
//		return nil
//	}
//	remotes, err := opts.Remotes()
//	if err != nil {
//		return nil
//	}
//	remote, err := remotes.FindByRepo(baseRepo.RepoOwner(), baseRepo.RepoName())
//	if err != nil {
//		return nil
//	}
//	return remote
//}

func mergeConflictStatus(status string) bool {
	return status == MergeStateStatusDirty
}

func isImmediatelyMergeable(status string) bool {
	switch status {
	case MergeStateStatusClean, MergeStateStatusHasHooks, MergeStateStatusUnstable:
		return true
	default:
		return false
	}
}

type mergePayload struct {
	repo            ghrepo.Interface
	pullRequestID   string
	method          PullRequestMergeMethod
	auto            bool
	commitSubject   string
	commitBody      string
	setCommitBody   bool
	expectedHeadOid string
	authorEmail     string
}

// TODO: drop after githubv4 gets updated
type EnablePullRequestAutoMergeInput struct {
	githubv4.MergePullRequestInput
}

// mergePullRequest is a helper function to actually merge the payload.
// N.B. This function supports all the different merge methods because the code was inherited from GitHub's cli
// so why not? But the higher APIs that call it don't support that.
func mergePullRequest(client *http.Client, payload mergePayload) error {
	input := githubv4.MergePullRequestInput{
		PullRequestID: githubv4.ID(payload.pullRequestID),
	}

	switch payload.method {
	case PullRequestMergeMethodMerge:
		m := githubv4.PullRequestMergeMethodMerge
		input.MergeMethod = &m
	case PullRequestMergeMethodRebase:
		m := githubv4.PullRequestMergeMethodRebase
		input.MergeMethod = &m
	case PullRequestMergeMethodSquash:
		m := githubv4.PullRequestMergeMethodSquash
		input.MergeMethod = &m
	}

	if payload.authorEmail != "" {
		authorEmail := githubv4.String(payload.authorEmail)
		input.AuthorEmail = &authorEmail
	}
	if payload.commitSubject != "" {
		commitHeadline := githubv4.String(payload.commitSubject)
		input.CommitHeadline = &commitHeadline
	}
	if payload.setCommitBody {
		commitBody := githubv4.String(payload.commitBody)
		input.CommitBody = &commitBody
	}

	if payload.expectedHeadOid != "" {
		expectedHeadOid := githubv4.GitObjectID(payload.expectedHeadOid)
		input.ExpectedHeadOid = &expectedHeadOid
	}

	variables := map[string]interface{}{
		"input": input,
	}

	gql := api.NewClientFromHTTP(client)

	if payload.auto {
		var mutation struct {
			EnablePullRequestAutoMerge struct {
				ClientMutationId string
			} `graphql:"enablePullRequestAutoMerge(input: $input)"`
		}
		variables["input"] = EnablePullRequestAutoMergeInput{input}
		return gql.Mutate(payload.repo.RepoHost(), "PullRequestAutoMerge", &mutation, variables)
	}

	var mutation struct {
		MergePullRequest struct {
			ClientMutationId string
		} `graphql:"mergePullRequest(input: $input)"`
	}
	return gql.Mutate(payload.repo.RepoHost(), "PullRequestMerge", &mutation, variables)
}

func disableAutoMerge(client *http.Client, repo ghrepo.Interface, prID string) error {
	var mutation struct {
		DisablePullRequestAutoMerge struct {
			ClientMutationId string
		} `graphql:"disablePullRequestAutoMerge(input: {pullRequestId: $prID})"`
	}

	variables := map[string]interface{}{
		"prID": githubv4.ID(prID),
	}

	gql := api.NewClientFromHTTP(client)
	return gql.Mutate(repo.RepoHost(), "PullRequestAutoMergeDisable", &mutation, variables)
}

// getMergeText gets the text for the merge.
// N.B. I think this mimics obtaining the text that would be autoconstructed for the PR if merged via the UI.
func getMergeText(client *http.Client, repo ghrepo.Interface, prID string, mergeMethod PullRequestMergeMethod) (string, string, error) {
	var method githubv4.PullRequestMergeMethod
	switch mergeMethod {
	case PullRequestMergeMethodMerge:
		method = githubv4.PullRequestMergeMethodMerge
	case PullRequestMergeMethodRebase:
		method = githubv4.PullRequestMergeMethodRebase
	case PullRequestMergeMethodSquash:
		method = githubv4.PullRequestMergeMethodSquash
	}

	var query struct {
		Node struct {
			PullRequest struct {
				ViewerMergeHeadlineText string `graphql:"viewerMergeHeadlineText(mergeType: $method)"`
				ViewerMergeBodyText     string `graphql:"viewerMergeBodyText(mergeType: $method)"`
			} `graphql:"...on PullRequest"`
		} `graphql:"node(id: $prID)"`
	}

	variables := map[string]interface{}{
		"prID":   githubv4.ID(prID),
		"method": method,
	}

	gql := api.NewClientFromHTTP(client)
	err := gql.Query(repo.RepoHost(), "PullRequestMergeText", &query, variables)
	if err != nil {
		// Tolerate this API missing in older GitHub Enterprise
		if strings.Contains(err.Error(), "Field 'viewerMergeHeadlineText' doesn't exist") ||
			strings.Contains(err.Error(), "Field 'viewerMergeBodyText' doesn't exist") {
			return "", "", nil
		}
		return "", "", err
	}

	return query.Node.PullRequest.ViewerMergeHeadlineText, query.Node.PullRequest.ViewerMergeBodyText, nil
}

var pullURLRE = regexp.MustCompile(`^/([^/]+)/([^/]+)/pull/(\d+)`)

func parsePRURL(prURL string) (ghrepo.Interface, int, error) {
	if prURL == "" {
		return nil, 0, fmt.Errorf("invalid URL: %q", prURL)
	}

	u, err := url.Parse(prURL)
	if err != nil {
		return nil, 0, err
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, 0, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	m := pullURLRE.FindStringSubmatch(u.Path)
	if m == nil {
		return nil, 0, fmt.Errorf("not a pull request URL: %s", prURL)
	}

	repo := ghrepo.NewWithHost(m[1], m[2], u.Hostname())
	prNumber, _ := strconv.Atoi(m[3])
	return repo, prNumber, nil
}
