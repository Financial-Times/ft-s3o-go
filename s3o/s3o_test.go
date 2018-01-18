package s3o

import (
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type helloWorld struct {
	mock.Mock
}

func (h *helloWorld) verify() {
	h.Called()
}

func (h *helloWorld) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello secure world"))
		h.verify()
	})
}

func TestS3oRedirectOverHTTP(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello-world", nil)

	hw := new(helloWorld)
	Handler(hw.handler()).ServeHTTP(w, r)
	checkCacheHeaders(t, w)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://s3o.ft.com/v2/authenticate/?post=true&redirect=http%3A%2F%2Fexample.com%2Fhello-world&host=example.com", w.Header().Get("Location"))

	hw.AssertExpectations(t)
}

func TestS3oRedirectOverHTTPS(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello-world", nil)

	r.Header.Add("X-Forwarded-Proto", "https")

	hw := new(helloWorld)

	Handler(hw.handler()).ServeHTTP(w, r)
	checkCacheHeaders(t, w)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://s3o.ft.com/v2/authenticate/?post=true&redirect=https%3A%2F%2Fexample.com%2Fhello-world&host=example.com", w.Header().Get("Location"))
	hw.AssertExpectations(t)
}

func TestS3oInvalidAuthDoesNotCallNextHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello-world", nil)

	r.AddCookie(&http.Cookie{Name: cookieUsernameKey, Value: "", Expires: time.Now()})
	r.AddCookie(&http.Cookie{Name: cookieTokenKey, Value: "", Expires: time.Now()})

	hw := new(helloWorld)
	Handler(hw.handler()).ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "public s3o key unavailable", w.Body.String())

	setCookies := w.HeaderMap[textproto.CanonicalMIMEHeaderKey("Set-Cookie")]
	for _, actual := range setCookies {
		if strings.HasPrefix(actual, cookieTokenKey) {
			assert.Contains(t, actual, cookieTokenKey+"=; Expires=")
		} else {
			assert.Contains(t, actual, cookieUsernameKey+"=; Expires=")
		}
	}

	hw.AssertExpectations(t)
}

func TestCheckCookiesFailsAndAttemptsAuthIfNoToken(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello-world", nil)

	r.AddCookie(&http.Cookie{Name: cookieUsernameKey, Value: "username", Expires: time.Now()})

	hw := new(helloWorld)
	Handler(hw.handler()).ServeHTTP(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://s3o.ft.com/v2/authenticate/?post=true&redirect=http%3A%2F%2Fexample.com%2Fhello-world&host=example.com", w.Header().Get("Location"))
	hw.AssertExpectations(t)
}

func TestCheckCookiesFailsAndAttemptsAuthIfNoUsername(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/hello-world", nil)

	r.AddCookie(&http.Cookie{Name: cookieTokenKey, Value: "", Expires: time.Now()})

	hw := new(helloWorld)
	Handler(hw.handler()).ServeHTTP(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://s3o.ft.com/v2/authenticate/?post=true&redirect=http%3A%2F%2Fexample.com%2Fhello-world&host=example.com", w.Header().Get("Location"))
	hw.AssertExpectations(t)
}

func checkCacheHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	assert.Equal(t, "private, no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "0", w.Header().Get("Expires"))
}
