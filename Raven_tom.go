package raven

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Identity uniquely represents a single raven user
type Identity struct {
	CrsID string
}

// Authenticator contains information required to verify a user's identity
type Authenticator struct {
	hostname string
	key      *rsa.PublicKey
	users    map[string]user

	cookieLife time.Duration
}

type user struct {
	crsID        string
	lastVerified time.Time
	uniqueCookie []byte
}

// https://github.com/cambridgeuniversity/UcamWebauth-protocol
const (
	ravenVersion   = 0
	ravenStatus    = 1
	ravenMessage   = 2
	ravenIssue     = 3
	ravenID        = 4
	ravenURL       = 5
	ravenPrincipal = 6
	ravenPtags     = 7
	ravenAuth      = 8
	ravenSSO       = 9
	ravenLife      = 10
	ravenParams    = 11
	ravenKeyID     = 12
	ravenSignature = 13

	ravenLength = 14
)

func getRSAKey(file string) (*rsa.PublicKey, error) {
	r, _ := ioutil.ReadFile(file)
	block, _ := pem.Decode(r)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func decodeRavenBase64(text string) ([]byte, error) {
	text = strings.ReplaceAll(text, "-", "+")
	text = strings.ReplaceAll(text, ".", "/")
	text = strings.ReplaceAll(text, "_", "=")
	return base64.StdEncoding.DecodeString(text)
}

func verifyViaRSA(key *rsa.PublicKey, messageStr, signatureStr string) bool {
	signatureData, _ := decodeRavenBase64(signatureStr)
	messageHash := sha1.Sum([]byte(messageStr))
	return rsa.VerifyPKCS1v15(key, crypto.SHA1, messageHash[:], signatureData) == nil
}

func (auth *Authenticator) isAuthorised(r *http.Request) (Identity, error) {
	crsID, err := r.Cookie("crsID")
	if err != nil {
		return Identity{}, fmt.Errorf("no crsid")
	}
	uniqueCookie, err := r.Cookie("authIdentity")
	if err != nil {
		return Identity{}, fmt.Errorf("no authIdentity found")
	}
	uniqueBytes, err := base64.StdEncoding.DecodeString(uniqueCookie.Value)
	if err != nil {
		return Identity{}, fmt.Errorf("invalid base64 encoding")
	}
	if user, ok := auth.users[crsID.Value]; ok {
		if time.Now().Sub(user.lastVerified) > auth.cookieLife {
			return Identity{}, fmt.Errorf("expired cookie")
		}
		//Random bytes are equal
		if bytes.Equal(user.uniqueCookie, uniqueBytes) {
			return Identity{crsID.Value}, nil
		}
	}
	return Identity{}, fmt.Errorf("failed authenticity check")
}

func (auth *Authenticator) getRavenInfo(authPath string, r *http.Request) (Identity, error) {
	values := r.URL.Query()
	val, ok := values["WLS-Response"]
	if !ok {
		return Identity{}, fmt.Errorf("WLS-Response not found")
	}
	parts := strings.Split(val[0], "!")
	if len(parts) != ravenLength {
		return Identity{}, fmt.Errorf("Invalid length")
	}
	if parts[ravenStatus] != "200" {
		return Identity{}, fmt.Errorf("Authentication failed")
	}
	if path, _ := url.PathUnescape(parts[ravenURL]); path != auth.hostname+authPath {
		// Raven requests need to be directed to the authentication url
		return Identity{}, fmt.Errorf("Invalid url")
	}

	// Mad format string, kinda like RFC3339 without the separators
	issueTime, _ := time.Parse("20060102T150405Z", parts[ravenIssue])
	if math.Abs(time.Now().Sub(issueTime).Hours()) < 1 {
		// Raven requests are valid for only one hour
		return Identity{}, fmt.Errorf("Raven confirmation is old")
	}

	url := strings.Join(parts[:ravenKeyID], "!")
	if !verifyViaRSA(auth.key, url, parts[ravenSignature]) {
		return Identity{}, fmt.Errorf("Failed RSA check")
	}
	return Identity{parts[ravenPrincipal]}, nil
}

func (auth *Authenticator) setAuthenticationCookie(identity Identity, w http.ResponseWriter, r *http.Request) {
	//64 byte random number
	uniqueCookie := make([]byte, 64)
	rand.Read(uniqueCookie)

	auth.users[identity.CrsID] = user{
		crsID:        identity.CrsID,
		lastVerified: time.Now(),
		uniqueCookie: uniqueCookie,
	}

	expiration := time.Now().Add(auth.cookieLife)
	http.SetCookie(w, &http.Cookie{
		Name:    "crsID",
		Value:   identity.CrsID,
		Expires: expiration,
		Path:    "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "authIdentity",
		Value:   base64.StdEncoding.EncodeToString(uniqueCookie),
		Expires: expiration,
		Path:    "/",
	})
}

// GetRavenLink returns a valid Raven url allowing users to authenticate
func (auth *Authenticator) GetRavenLink(authPath string) string {
	ravenRequest, _ := url.Parse("https://raven.cam.ac.uk/auth/authenticate.html")

	q := ravenRequest.Query()
	q.Add("ver", "3")
	q.Add("url", auth.hostname+authPath)
	q.Add("iact", "yes")

	ravenRequest.RawQuery = q.Encode()

	return ravenRequest.String()
}

// SetLifetime sets the time a user can remain authenticated after Raven verification
func (auth *Authenticator) SetLifetime(duration time.Duration) {
	auth.cookieLife = duration
}

// HandleAuthenticationPath listens for and validates raven requests
func (auth *Authenticator) HandleAuthenticationPath(authPath string, handler func(Identity, http.ResponseWriter, *http.Request), failed func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(authPath, func(w http.ResponseWriter, r *http.Request) {
		identity, err := auth.getRavenInfo(authPath, r)
		if err != nil {
			//Permission denied
			failed(w, r)
			return
		}
		auth.setAuthenticationCookie(identity, w, r)
		handler(identity, w, r)
	})
}

// AuthoriseAndHandle ensures user has valid authentication cookies before handling request
func (auth *Authenticator) AuthoriseAndHandle(urlPath string, handler func(Identity, http.ResponseWriter, *http.Request), failed func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		if identity, err := auth.isAuthorised(r); err == nil {
			handler(identity, w, r)
			return
		}
		failed(w, r)
	})
}

// NewAuthenticator loads Raven's RSA key from a file and enables authentication
func NewAuthenticator(protocol string, hostname string, keyPath string) Authenticator {
	key, err := getRSAKey(keyPath)
	if err != nil {
		panic("Error reading RSA key!")
	}
	return Authenticator{
		hostname: protocol + "://" + hostname,
		key:      key,
		users:    make(map[string]user),

		cookieLife: time.Hour * 24,
	}
}