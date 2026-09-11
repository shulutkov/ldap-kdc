package store

import "github.com/pquerna/otp/totp"

// Outcome is what presenting a credential amounted to. The values are the labels the callers
// already count by, so a new door reports in the same vocabulary as the old one.
type Outcome string

const (
	// OutcomeOK is the account's own password, with a valid one-time code where one is required.
	OutcomeOK Outcome = "ok"
	// OutcomeAppPassword is one of the account's application passwords, presented whole.
	OutcomeAppPassword Outcome = "ok-app-password"
	// OutcomeBadOTP is the right password with the wrong (or missing) one-time code.
	OutcomeBadOTP Outcome = "bad-otp"
	// OutcomeInvalid is the wrong password, or an account that has none and therefore cannot
	// authenticate at all.
	OutcomeInvalid Outcome = "invalid"
	// OutcomeDisabled is an account that exists and is switched off.
	OutcomeDisabled Outcome = "disabled"
)

// Granted reports whether the outcome let the account in.
func (o Outcome) Granted() bool { return o == OutcomeOK || o == OutcomeAppPassword }

// Authenticate decides whether presented authenticates u.
//
// It is the WHOLE decision and it lives here because more than one door asks it — the LDAP bind
// and the OIDC login form — and two doors that decide credentials separately are two doors that
// eventually disagree. That is the failure this service exists to prevent, only spelled with
// protocols instead of digests: an account that binds but cannot sign in reads as a broken
// account, not as two copies of one rule drifting apart.
//
// What it does NOT do is anything about the request: rate limiting, logging and metrics belong to
// the door, which knows where the attempt came from and how to answer it.
//
// The shape of the credential is the LDAP convention and is kept: a one-time code, where the
// account has a secret, is the last six characters of the string rather than a separate field,
// because a simple bind has nowhere else to put it. An application password is presented whole and
// carries no code — it exists for a client that cannot be handed one.
func Authenticate(u *User, presented string) Outcome {
	if u.Disabled {
		return OutcomeDisabled
	}

	password := presented
	otpValid := len(u.OTPSecret) == 0

	if len(u.OTPSecret) > 0 && len(presented) > 6 {
		code := presented[len(presented)-6:]
		password = presented[:len(presented)-6]
		otpValid = totp.Validate(code, u.OTPSecret)
	}

	for _, ap := range u.AppPasswords {
		if CheckPassword(ap.Hash, presented) {
			return OutcomeAppPassword
		}
	}

	if !otpValid {
		return OutcomeBadOTP
	}

	// An account with no digest cannot authenticate at all. Falling through to success here would
	// let every account created but never given a password in with anything.
	if len(u.PassBcrypt) == 0 || !CheckPassword(u.PassBcrypt, password) {
		return OutcomeInvalid
	}

	return OutcomeOK
}
