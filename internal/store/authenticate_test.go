package store

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func userWith(t *testing.T, password string) *User {
	t.Helper()
	u := &User{Name: "alice"}
	if password != "" {
		h, err := hashPassword(password, 4) // cheap on purpose: this tests the decision, not bcrypt
		if err != nil {
			t.Fatal(err)
		}
		u.PassBcrypt = h
	}
	return u
}

func TestAuthenticate(t *testing.T) {
	secret, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	appHash, err := hashPassword("an application password", 4)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		user      func() *User
		presented string
		want      Outcome
	}{
		{
			name:      "the account's own password",
			user:      func() *User { return userWith(t, "correct horse battery staple") },
			presented: "correct horse battery staple",
			want:      OutcomeOK,
		},
		{
			name:      "the wrong password",
			user:      func() *User { return userWith(t, "correct horse battery staple") },
			presented: "wrong",
			want:      OutcomeInvalid,
		},
		{
			name: "a disabled account is refused before anything else is asked",
			user: func() *User {
				u := userWith(t, "correct horse battery staple")
				u.Disabled = true
				return u
			},
			presented: "correct horse battery staple",
			want:      OutcomeDisabled,
		},
		{
			// The one that matters most: an account created but never given a password must not
			// authenticate with anything at all.
			name:      "no digest at all",
			user:      func() *User { return userWith(t, "") },
			presented: "anything",
			want:      OutcomeInvalid,
		},
		{
			name: "an application password is presented whole and carries no code",
			user: func() *User {
				u := userWith(t, "correct horse battery staple")
				u.OTPSecret = secret.Secret()
				u.AppPasswords = []AppPassword{{Name: "backup", Hash: appHash}}
				return u
			},
			presented: "an application password",
			want:      OutcomeAppPassword,
		},
		{
			name: "the password with a valid one-time code appended",
			user: func() *User {
				u := userWith(t, "correct horse battery staple")
				u.OTPSecret = secret.Secret()
				return u
			},
			presented: "correct horse battery staple" + code,
			want:      OutcomeOK,
		},
		{
			name: "the right password with the wrong code",
			user: func() *User {
				u := userWith(t, "correct horse battery staple")
				u.OTPSecret = secret.Secret()
				return u
			},
			presented: "correct horse battery staple" + "000000",
			want:      OutcomeBadOTP,
		},
		{
			// Where a secret is set the tail is ALWAYS read as the code, so a password presented
			// without one reads as a bad code rather than a bad password. It is the LDAP bind's
			// long-standing behaviour and is pinned here because the new door inherits it.
			name: "the right password with no code at all, where one is required",
			user: func() *User {
				u := userWith(t, "correct horse battery staple")
				u.OTPSecret = secret.Secret()
				return u
			},
			presented: "correct horse battery staple",
			want:      OutcomeBadOTP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Authenticate(tc.user(), tc.presented)
			if got != tc.want {
				t.Errorf("Authenticate = %q, want %q", got, tc.want)
			}
			if got.Granted() != (tc.want == OutcomeOK || tc.want == OutcomeAppPassword) {
				t.Errorf("Granted() disagrees with the outcome %q", got)
			}
		})
	}
}
