package s3o

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	cookieUsernameKey = "s3o_username"
	cookieTokenKey    = "s3o_token"
)

var (
	lk     sync.RWMutex
	pubKey *rsa.PublicKey
	period = time.Duration(5 * time.Minute)
)

func init() {
	go periodicFetchKey()
}

func periodicFetchKey() {
	for {
		newPubKey, err := fetchPubkey()
		if err != nil {
			log.Printf("failed to fetch s3o public key: %s\n", err.Error())
		} else {
			lk.Lock()
			pubKey = newPubKey
			lk.Unlock()
		}
		lk.RLock()
		p := period
		lk.RUnlock()
		time.Sleep(p)
	}
}

func fetchPubkey() (*rsa.PublicKey, error) {
	resp, err := http.Get("https://s3o.ft.com/publickey")
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to read s3o public key")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, errors.New("failed to read s3o public key")
	}
	dec := make([]byte, 8192) // should be enough for a while.
	i, err := base64.StdEncoding.Decode(dec, buf.Bytes())
	if err != nil {
		return nil, errors.New("failed to base64 decode s3o public key")
	}

	pub, err := x509.ParsePKIXPublicKey(dec[0:i])
	if err != nil {
		return nil, errors.New("failed to parse s3o public key")
	}
	return pub.(*rsa.PublicKey), nil
}

// Handler wraps the given handler in s3o authentication
func Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user := r.Form.Get("username")
		token := r.Form.Get("token")

		// These parameters come from https://s3o.ft.com. It redirects back after it does the google authentication.
		if r.Method == "POST" && user != "" {
			code, err := authenticateToken(user, token, r.Host)
			if err != nil {
				w.WriteHeader(code)
				fmt.Fprint(w, err.Error())
			}

			// set cookies
			http.SetCookie(w, &http.Cookie{Name: cookieUsernameKey, Value: user, MaxAge: 900000, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: cookieTokenKey, Value: token, MaxAge: 900000, HttpOnly: true})

			// s3o.ft.com redirects with ?username=<value> query param, so we're going to remove it from the URL
			cleanURL := cleanUsernameFromURL(r, user)

			// don't cache any redirection responses
			w.Header().Add("Cache-Control", "private, no-cache, no-store, must-revalidate")
			w.Header().Add("Pragma", "no-cache")
			w.Header().Add("Expires", "0")

			// make a copy of original request, with clean URL
			req, _ := http.NewRequest(http.MethodGet, cleanURL, nil)

			// redirect to the original request
			http.Redirect(w, req, cleanURL, http.StatusFound)
		} else if hasCookies, usr, tkn := isAuthFromCookie(r); hasCookies {
			// check for s3o username/token cookies
			code, err := authenticateToken(usr, tkn, r.Host)
			if err != nil {
				deleteCookie(w, cookieUsernameKey, r)
				deleteCookie(w, cookieTokenKey, r)

				w.WriteHeader(code)
				fmt.Fprint(w, err.Error())
				return
			}
			next.ServeHTTP(w, r)
		} else {
			// send the user to s3o to authenticate
			proto := "http"
			if r.Header.Get("X-Forwarded-Proto") == "https" || r.Header.Get(":scheme") == "https" {
				proto = "https"
			}
			query := ""
			if r.URL.RawQuery != "" {
				query = "?" + r.URL.RawQuery
			}
			// not worrying about including r.URL.Fragment
			originalLocation := fmt.Sprintf("%s://%s%s%s", proto, r.Host, r.URL.Path, query)

			w.Header().Add("Cache-Control", "private, no-cache, no-store, must-revalidate")
			w.Header().Add("Pragma", "no-cache")
			w.Header().Add("Expires", "0")
			http.Redirect(w, r, "https://s3o.ft.com/v2/authenticate/?post=true&redirect="+url.QueryEscape(originalLocation)+"&host="+url.QueryEscape(r.Host), http.StatusFound)
		}
	})
}

func deleteCookie(w http.ResponseWriter, cookieName string, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}

	c.Value = ""
	c.Expires = time.Now().Add(time.Hour * -1)
	http.SetCookie(w, c) // attempt to set an empty value cookie with an out-of-date expiry to force the browser to delete it
}

func cleanUsernameFromURL(r *http.Request, username string) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	// cleaning username param
	query := strings.Replace(r.URL.RawQuery, "username="+username, "", -1)
	if query != "" {
		query = "?" + query
	}

	// remains unchanged if not ending in "&"
	query = strings.TrimSuffix(query, "&")

	// path '/' keeps the query params unchanged when redirecting
	path := r.URL.EscapedPath()
	if path == "/" {
		path = ""
	}

	return fmt.Sprintf("%s://%s%s%s", proto, r.Host, path, query)
}

func isAuthFromCookie(r *http.Request) (bool, string, string) {
	usr, err1 := r.Cookie(cookieUsernameKey)
	tkn, err2 := r.Cookie(cookieTokenKey)
	if err1 != nil || err2 != nil {
		return false, "", ""
	}
	return true, usr.Value, tkn.Value
}

func authenticateToken(username string, token string, hostname string) (int, error) {
	sig, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return http.StatusForbidden, errors.New("failed to decode auth token")
	}

	hash := sha1.New()
	if _, err := hash.Write([]byte(username + "-" + hostname)); err != nil {
		return http.StatusInternalServerError, errors.New("failed to hash user")
	}

	lk.RLock()
	defer lk.RUnlock()

	if pubKey == nil {
		return http.StatusForbidden, errors.New("public s3o key unavailable")
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash.Sum(nil), sig); err != nil {
		return http.StatusForbidden, errors.New("failed to authenticate")
	}

	return 0, nil
}

// SetKeyFetchPeriod changes how often we fetch the s3o public key. The default is 5 minutes.
func SetKeyFetchPeriod(d time.Duration) {
	lk.Lock()
	defer lk.Unlock()
	period = d
}
