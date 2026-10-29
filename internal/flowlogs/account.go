package flowlogs

import (
	"errors"
	"strings"
	"time"
)

// Account is one storage account the poller reads, by name, for logs and blob keys.
type Account struct {
	Name  string
	Store BlobStore
}

// account is an Account as the poller tracks it. Blobs are keyed in the state by name: the
// first account's by their blob name alone, so a state file written when the sensor read one
// account keeps working, and every other account's under its prefix, @<name>/. Azure's flow log
// blob names start with flowLogResourceID=, so a prefix never matches one.
type account struct {
	Account
	prefix string
	// roots are the flow log roots found by the last full listing, at rootsAt
	roots   []string
	rootsAt time.Time
	// listErr is the last listing failure, at listFailedAt, until a listing succeeds
	listErr      error
	listFailedAt time.Time
}

func newAccounts(in []Account) []*account {
	out := make([]*account, len(in))
	for i, a := range in {
		out[i] = &account{Account: a}
		if i > 0 {
			out[i].prefix = "@" + a.Name + "/"
		}
	}
	return out
}

// key is the state's key for one of this account's blobs.
func (a *account) key(name string) string {
	return a.prefix + name
}

// owner returns the account a blob key belongs to and the blob's name in it. A key with no
// configured account's prefix belongs to the first account.
func (p *Poller) owner(key string) (*account, string) {
	for _, a := range p.accounts[1:] {
		if name, ok := strings.CutPrefix(key, a.prefix); ok {
			return a, name
		}
	}
	return p.accounts[0], key
}

// accountError is a failure in one account, when the poller reads more than one.
type accountError struct {
	account string
	err     error
}

func (e *accountError) Error() string { return "storage account " + e.account + ": " + e.err.Error() }
func (e *accountError) Unwrap() error { return e.err }

// wrap names the account in err, when there is more than one to tell apart.
func (p *Poller) wrap(a *account, err error) error {
	if len(p.accounts) == 1 {
		return err
	}
	return &accountError{account: a.Name, err: err}
}

// failedAccount returns the account err happened in, or "" when it is not about one account.
func failedAccount(err error) string {
	var ae *accountError
	if errors.As(err, &ae) {
		return ae.account
	}
	return ""
}
