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
	"sync"
	"time"
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

		// Send the user to s3o to authenticate
		if user == "" || token == "" {
			log.Printf("Starting authentication for url: %s", r.URL)
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			query := ""
			if r.URL.RawQuery != "" {
				query = "?" + r.URL.RawQuery
			}
			// not worrying about including r.URL.Fragment

			requrl := fmt.Sprintf("%s://%s%s%s", proto, r.Host, r.URL.Path, query)

			w.Header().Add("Cache-Control", "private, no-cache, no-store, must-revalidate")
			w.Header().Add("Pragma", "no-cache")
			w.Header().Add("Expires", "0")
			http.Redirect(w, r, "https://s3o.ft.com/v2/authenticate/?post=true&redirect="+url.QueryEscape(requrl)+"&host="+url.QueryEscape(r.Host), http.StatusFound)
			return
		}

		// These parameters come from https://s3o.ft.com. It redirects back after it does the google authentication.
		if r.Method == "POST" && user != "" {
			log.Printf("POST with url: %s", r.URL)
			sig, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "failed to decode auth token")
				return
			}

			hash := sha1.New()
			if _, err := hash.Write([]byte(user + "-" + r.Host)); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "failed to hash user")
				return
			}

			lk.RLock()
			defer lk.RUnlock()

			if pubKey == nil {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "public s3o key unavailable")
				return
			}

			if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash.Sum(nil), sig); err != nil {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "failed to authenticate")
				return
			}

			// set cookies
			http.SetCookie(w, &http.Cookie{Name: "s3o_username", Value: user, MaxAge: 900000, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: "s3o_token", Value: token, MaxAge: 900000, HttpOnly: true})
			// clean URL
			//cleanURL = url.parse(req.originalUrl, true);
		}
	})
}

// SetKeyFetchPeriod changes how often we fetch the s3o public key. The default is 5 minutes.
func SetKeyFetchPeriod(d time.Duration) {
	lk.Lock()
	defer lk.Unlock()
	period = d
}
