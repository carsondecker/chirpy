package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckPasswordHash(t *testing.T) {
	cases := []struct {
		password          string
		attemptedPassword string
		err               bool
	}{
		{
			password:          "123abcABC",
			attemptedPassword: "123abcABC",
			err:               false,
		},
		{
			password:          "password",
			attemptedPassword: "wrongpassword",
			err:               true,
		},
	}

	for i, c := range cases {
		hash, _ := HashPassword(c.password)
		err := CheckPasswordHash(c.attemptedPassword, hash)
		if (err != nil) != c.err {
			t.Errorf("error status is incorrect in case %d", i)
		}
	}
}

func TestValidateJWT(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()

	cases := []struct {
		userID       uuid.UUID
		tokenSecret  string
		expiresIn    time.Duration
		tokenSecret2 string
		waitTime     time.Duration
		expected     uuid.UUID
		expectError  bool
	}{
		{
			userID:       id1,
			tokenSecret:  "abcABC123!@#",
			expiresIn:    time.Second,
			tokenSecret2: "abcABC123!@#",
			waitTime:     time.Nanosecond,
			expected:     id1,
			expectError:  false,
		},
		{
			userID:       id2,
			tokenSecret:  "123abcABC123",
			expiresIn:    time.Second,
			tokenSecret2: "abcABC123!@#",
			waitTime:     time.Nanosecond,
			expected:     uuid.Nil,
			expectError:  true,
		},
		{
			userID:       id3,
			tokenSecret:  "aaaa",
			expiresIn:    time.Second,
			tokenSecret2: "aaaa",
			waitTime:     time.Second * 2,
			expected:     uuid.Nil,
			expectError:  true,
		},
	}

	for i, c := range cases {
		token, err := MakeJWT(c.userID, c.tokenSecret, c.expiresIn)
		if err != nil {
			t.Errorf("failed to make jwt on case %d: %v", i, err)
		}

		time.Sleep(c.waitTime)

		id, err := ValidateJWT(token, c.tokenSecret2)

		t.Logf("Case %d: Expected=%v, Got=%v, Error=%v", i, c.expected, id, err)

		if c.expectError {
			if err == nil {
				t.Errorf("case %d: expected error but got none", i)
			}
			if id != uuid.Nil {
				t.Errorf("case %d: expected uuid.Nil but got %v", i, id)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: unexpected error: %v", i, err)
			}
			if id != c.expected {
				t.Errorf("case %d: expected uuid %v but got %v", i, c.expected, id)
			}
		}
	}
}
