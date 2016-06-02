package s3o

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var pubKey *rsa.PublicKey

func init() {
	resp, err := http.Get("https://s3o.ft.com/publickey")
	if err != nil || resp.StatusCode != http.StatusOK {
		panic("failed to read s3o public key")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		panic("failed to read s3o public key")
	}
	dec := make([]byte, 8192) // should be enough for a while.
	i, err := base64.StdEncoding.Decode(dec, buf.Bytes())
	if err != nil {
		panic("failed to base64 decode s3o public key")
	}

	pub, err := x509.ParsePKIXPublicKey(dec[0:i])
	if err != nil {
		panic("failed to parse s3o public key")
	}
	pubKey = pub.(*rsa.PublicKey)
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

		if user == "" || token == "" {
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			requrl := fmt.Sprintf("%s://%s%s", proto, r.Host, r.URL.Path)
			w.Header().Add("Cache-Control", "private, no-cache, no-store, must-revalidate")
			w.Header().Add("Pragma", "no-cache")
			w.Header().Add("Expires", "0")
			http.Redirect(w, r, "https://s3o.ft.com/v2/authenticate/?redirect="+url.QueryEscape(requrl)+"&host="+url.QueryEscape(r.Host), http.StatusFound)
			return
		}

		sig, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			fmt.Fprint(w, "failed to decode auth token")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		hash := sha1.New()
		if _, err := hash.Write([]byte(user + "-" + r.Host)); err != nil {
			fmt.Fprint(w, "failed to hash user")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash.Sum(nil), sig); err != nil {
			fmt.Fprint(w, "failed to authenticate")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
