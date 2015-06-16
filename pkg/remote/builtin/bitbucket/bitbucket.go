package bitbucket

import (

	"github.com/drone/drone/pkg/config"
	common "github.com/drone/drone/pkg/types"
	"github.com/drone/go-bitbucket/bitbucket"
	"net/url"
	"net/http"
	"fmt"
	"time"
	"regexp"

	log "github.com/Sirupsen/logrus"
)

const (
	DefaultAPI = "https://api.bitbucket.org/1.0"
	DefaultURL = "https://bitbucket.org"
)

// parses an email address from string format
// `John Doe <john.doe@example.com>`
var emailRegexp = regexp.MustCompile("<(.*)>")

type Bitbucket struct {
	URL    string
	API    string
	Client string
	Secret string
	Open   bool
}

func New(conf *config.Config) *Bitbucket {
	var bitbucket = Bitbucket{
		API:         DefaultAPI,
		URL:         DefaultURL,
		Client:      conf.Auth.Client,
		Secret:      conf.Auth.Secret,
		Open:        conf.Remote.Open,
	}
	return &bitbucket
}

func (b *Bitbucket) Login(token, secret string) (*common.User, error) {
	// create the Bitbucket client
	client := bitbucket.New(
		b.Client,
		b.Secret,
		token,
		secret,
	)


	login, err := client.Users.Current()
	if err != nil {
		return nil, err
	}

	user := common.User{}
	user.Login = login.User.Username
	user.Name = login.User.DisplayName
	user.Token = token
	user.Secret = secret

	email, _ := client.Emails.FindPrimary(login.User.Username)
	if email != nil {
		user.Email = email.Email
	}

	return &user, nil
}

// Orgs fetches the organizations for the given user.
func (b *Bitbucket) Orgs(u *common.User) ([]string, error) {
	/*client := NewClient(g.API, u.Token, g.SkipVerify)
	orgs_ := []string{}
	orgs, err := GetOrgs(client)
	if err != nil {
		return orgs_, err
	}
	for _, org := range orgs {
		orgs_ = append(orgs_, *org.Login)
	}*/
	return nil, nil
}

// Repo fetches the named repository from the remote system.
func (b *Bitbucket) Repo(u *common.User, owner, name string) (*common.Repo, error) {
	client := bitbucket.New(
		b.Client,
		b.Secret,
		u.Token,
		u.Secret,
	)

	repo_, err := client.Repos.Find(owner, name)
	if err != nil {
		return nil, err
	}

	repo := &common.Repo{}
	repo.Owner = owner
	repo.Name = name
	repo.FullName = owner + "/" + name
	repo.Link = repo_.Scm
	repo.Private = repo_.Private
	repo.Clone = repo_.Scm
	repo.Language = repo_.Language

	return repo, err
}

// Perm fetches the named repository permissions from
// the remote system for the specified user.
func (b *Bitbucket) Perm(u *common.User, owner, name string) (*common.Perm, error) {
	/*key := fmt.Sprintf("%s/%s/%s", u.Login, owner, name)
	val, ok := g.cache.Get(key)
	if ok {
		return val.(*common.Perm), nil
	}

	client := NewClient(g.API, u.Token, g.SkipVerify)
	repo, err := GetRepo(client, owner, name)
	if err != nil {
		return nil, err
	}*/
	m := &common.Perm{}
	m.Admin = true
	m.Push = true
	m.Pull = true

	return m, nil
}

// Script fetches the build script (.drone.yml) from the remote
// repository and returns in string format.
func (b *Bitbucket) Script(u *common.User, r *common.Repo, c *common.Commit) ([]byte, error) {
	client := bitbucket.New(
		b.Client,
		b.Secret,
		u.Token,
		u.Secret,
	)

	// get the yaml from the database
	log.Infof("asddsasad saddasdasasdand running build %s", c.Sha)
	var raw, err = client.Sources.Find(r.Owner, r.Name, c.Sha, ".drone.yml")
	if err != nil {
		return nil, err
	}

	return []byte(raw.Data), nil
}

// Netrc returns a .netrc file that can be used to clone
// private repositories from a remote system.
func (b *Bitbucket) Netrc(u *common.User) (*common.Netrc, error) {
	url_, err := url.Parse(b.URL)
	if err != nil {
		return nil, err
	}
	netrc := &common.Netrc{}
	netrc.Login = u.Token
	netrc.Password = "x-oauth-basic"
	netrc.Machine = url_.Host
	return netrc, nil
}

// Activate activates a repository by creating the post-commit hook and
// adding the SSH deploy key, if applicable.
func (b *Bitbucket) Activate(u *common.User, r *common.Repo, k *common.Keypair, link string) error {
	client := bitbucket.New(
		b.Client,
		b.Secret,
		u.Token,
		u.Secret,
	)

	// parse the hostname from the hook, and use this
	// to name the ssh key
	var hookurl, err = url.Parse(link)
	if err != nil {
		return err
	}

	// if the CloneURL is using the SSHURL then we know that
	// we need to add an SSH key to GitHub.
	if r.Private {
		// name the key
		var keyname = "drone@" + hookurl.Host
		var _, err = client.RepoKeys.CreateUpdate(r.Owner, r.Name, r.PublicKey, keyname)
		if err != nil {
			return err
		}
	}

	// add the hook
	_, err = client.Brokers.CreateUpdate(r.Owner, r.Name, link, bitbucket.BrokerTypePost)
	return err
}

// Deactivate removes a repository by removing all the post-commit hooks
// which are equal to link and removing the SSH deploy key.
func (b *Bitbucket) Deactivate(u *common.User, r *common.Repo, link string) error {
	client := bitbucket.New(
		b.Client,
		b.Secret,
		u.Token,
		u.Secret,
	)

	title, err := GetKeyTitle(link)
	if err != nil {
		return err
	}

	// remove the deploy-key if it is installed remote.
	if r.Private {
		if err := client.RepoKeys.DeleteName(r.Owner, r.Name, title); err != nil {
			return err
		}
	}

	return client.Brokers.DeleteUrl(r.Owner, r.Name, link, bitbucket.BrokerTypePost)
}

func (b *Bitbucket) Status(u *common.User, r *common.Repo, c *common.Commit) error {
	/*client := NewClient(g.API, u.Token, g.SkipVerify)

	link := fmt.Sprintf("%s/%v", r.Self, c.Sequence)
	status := getStatus(c.State)
	desc := getDesc(c.State)
	data := github.RepoStatus{
		Context:     github.String("Drone"),
		State:       github.String(status),
		Description: github.String(desc),
		TargetURL:   github.String(link),
	}
	_, _, err := client.Repositories.CreateStatus(r.Owner, r.Name, c.SourceSha, &data)*/
	return nil
}

// Hook parses the post-commit hook from the Request body
// and returns the required data in a standard format.
func (b *Bitbucket) Hook(r *http.Request) (*common.Hook, error) {
	var payload = r.FormValue("payload")
	var hook, err = bitbucket.ParseHook([]byte(payload))
	if err != nil {
		return nil, err
	}

	// verify the payload has the minimum amount of required data.
	if hook.Repo == nil || hook.Commits == nil || len(hook.Commits) == 0 {
		return nil, fmt.Errorf("Invalid Bitbucket post-commit Hook. Missing Repo or Commit data.")
	}

	var author = hook.Commits[len(hook.Commits)-1].RawAuthor
	var matches = emailRegexp.FindStringSubmatch(author)
	if len(matches) == 2 {
		author = matches[1]
	}

	repo := &common.Repo{}
	repo.Owner = hook.Repo.Owner
	if len(repo.Owner) == 0 {
		repo.Owner = hook.Repo.Name
	}
	repo.Name = hook.Repo.Name
	repo.FullName = hook.Repo.Owner + "/" + hook.Repo.Name
	repo.Link = hook.Repo.Scm
	repo.Private = hook.Repo.Private
	repo.Clone = hook.Url
	repo.Language = hook.Repo.Language
	repo.Branch = hook.Repo.Scm

	commit := &common.Commit{}
	commit.Sha = hook.Commits[len(hook.Commits)-1].Hash
	commit.Ref = hook.Commits[len(hook.Commits)-1].Branch
	commit.Branch = hook.Commits[len(hook.Commits)-1].Branch
	commit.Message = hook.Commits[len(hook.Commits)-1].Message
	commit.Timestamp = time.Now().UTC().String()
	commit.Author = author

	return &common.Hook{Repo: repo, Commit: commit}, nil
}