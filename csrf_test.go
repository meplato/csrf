package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testKey = []byte("keep-it-secret-keep-it-safe-----")
var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// TestProtect is a high-level test to make sure the middleware returns the
// wrapped handler with a 200 OK status.
func TestProtect(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p := Protect(testKey)(s)
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie,
		"Secure") {
		t.Fatalf("cookie does not default to Secure & HttpOnly: got %v", cookie)
	}
}

// TestCookieOptions is a test to make sure the middleware correctly sets cookie options
func TestCookieOptions(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p := Protect(testKey,
		CookieName("nameoverride"),
		Secure(false),
		HttpOnly(false),
		Path("/pathoverride"),
		Domain("domainoverride"),
		MaxAge(173),
	)(s)
	p.ServeHTTP(rr, r)

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie does not respect HttpOnly option: got %v do not want HttpOnly", cookie)
	}
	if strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie does not respect Secure option: got %v do not want Secure", cookie)
	}
	if !strings.Contains(cookie, "nameoverride=") {
		t.Fatalf("cookie does not respect CookieName option: got %v want %v", cookie, "nameoverride=")
	}
	if !strings.Contains(cookie, "Domain=domainoverride") {
		t.Fatalf("cookie does not respect Domain option: got %v want %v", cookie, "Domain=domainoverride")
	}
	if !strings.Contains(cookie, "Max-Age=173") {
		t.Fatalf("cookie does not respect MaxAge option: got %v want %v", cookie, "Max-Age=173")
	}
}

// Test that idempotent methods return a 200 OK status and that non-idempotent
// methods return a 403 Forbidden status when a CSRF cookie is not present.
func TestMethods(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	// Test idempontent ("safe") methods
	for _, method := range safeMethods {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

	// Test non-idempotent methods (should return a 403 without a cookie set)
	nonIdempotent := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range nonIdempotent {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}
}

// Tests for failure if the cookie containing the session does not exist on a
// POST request.
func TestNoCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	// POST the token back in the header.
	r, err := http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a non-existent cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadCookie tests for failure when a cookie header is modified (malformed).
func TestBadCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the cookie prefix
	badHeader := strings.Replace(cookieName+"=", rr.Header().Get("Set-Cookie"), "_badCookie", -1)
	r.Header.Set("Cookie", badHeader)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a bad cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// Responses should set a "Vary: Cookie" header to protect client/proxy caching.
func TestVaryHeader(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r, err := http.NewRequest("HEAD", "https://www.golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Vary") != "Cookie" {
		t.Fatalf("vary header not set: got %q want %q", rr.Header().Get("Vary"), "Cookie")
	}
}

// Requests with no Referer header should fail.
func TestNoReferer(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r, err := http.NewRequest("POST", "https://golang.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject an empty Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly fail CSRF validation.
func TestBadReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://golang.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestTrustedReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly but is a trusted origin pass CSRF validation.
func TestTrustedReferer(t *testing.T) {
	testTable := []struct {
		trustedOrigin []string
		shouldPass    bool
	}{
		{[]string{"golang.org"}, true},
		{[]string{"api.example.com", "golang.org"}, true},
		{[]string{"http://golang.org"}, false},
		{[]string{"https://golang.org"}, false},
		{[]string{"http://example.com"}, false},
		{[]string{"example.com"}, false},
	}

	for _, item := range testTable {
		s := http.NewServeMux()

		p := Protect(testKey, TrustedOrigins(item.trustedOrigin))(s)

		var token string
		s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = Token(r)
		}))

		// Obtain a CSRF cookie via a GET request.
		r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		// POST the token back in the header.
		r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/", nil)
		if err != nil {
			t.Fatal(err)
		}

		setCookie(rr, r)
		r.Header.Set("X-CSRF-Token", token)

		// Set a non-matching Referer header.
		r.Header.Set("Referer", "http://golang.org/")

		rr = httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if item.shouldPass {
			if rr.Code != http.StatusOK {
				t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
					rr.Code, http.StatusOK)
			}
		} else {
			if rr.Code != http.StatusForbidden {
				t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
					rr.Code, http.StatusForbidden)
			}
		}
	}
}

// Requests with a valid Referer should pass.
func TestWithReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

// Requests without a token should fail with ErrNoToken.
func TestNoTokenProvided(t *testing.T) {
	var finalErr error

	s := http.NewServeMux()
	p := Protect(testKey, ErrorHandler(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		finalErr = FailureReason(r)
	})))(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	// By accident we use the wrong header name for the token...
	r.Header.Set("X-CSRF-nekot", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if finalErr != nil && finalErr != ErrNoToken {
		t.Fatalf("middleware failed to return correct error: got '%v' want '%v'", finalErr, ErrNoToken)
	}
}

func setCookie(rr *httptest.ResponseRecorder, r *http.Request) {
	r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
}

// TestTrustedRefererCallback checks that HTTPS requests with a Referer that does not
// match the request URL correctly but is a trusted origin callback pass CSRF validation.
func TestTrustedRefererCallback(t *testing.T) {
	testTable := []struct {
		prepare    func(*http.Request)
		callback   TrustedOriginsCallbackFunc
		shouldPass bool
	}{
		{
			callback: func(referer *url.URL, r *http.Request) bool {
				return referer.Host == "golang.org"
			},
			shouldPass: true,
		},
		{
			callback: func(referer *url.URL, r *http.Request) bool {
				return referer.Host == "golang.org" || referer.Host == "api.example.com"
			},
			shouldPass: true,
		},
		{
			callback: func(referer *url.URL, r *http.Request) bool {
				return referer.Host == "example.com"
			},
			shouldPass: false,
		},
		{
			prepare: func(r *http.Request) {
				r.Header.Set("X-Skip-CSRF", "true")
			},
			callback: func(referer *url.URL, r *http.Request) bool {
				// Not a good idea to do this, but it should work.
				return r.Header.Get("X-Skip-CSRF") == "true"
			},
			shouldPass: true,
		},
	}

	for i, item := range testTable {
		s := http.NewServeMux()

		p := Protect(testKey, TrustedOriginsCallback(item.callback))(s)

		var token string
		s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = Token(r)
		}))

		// Obtain a CSRF cookie via a GET request.
		r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		// POST the token back in the header.
		r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/", nil)
		if err != nil {
			t.Fatal(err)
		}

		setCookie(rr, r)
		r.Header.Set("X-CSRF-Token", token)

		// Set a non-matching Referer header.
		r.Header.Set("Referer", "http://golang.org/")

		// Prepare the request.
		if item.prepare != nil {
			item.prepare(r)
		}

		rr = httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if item.shouldPass {
			if rr.Code != http.StatusOK {
				t.Fatalf("test case #%d. middleware failed to pass to the next handler: got %v want %v",
					i, rr.Code, http.StatusOK)
			}
		} else {
			if rr.Code != http.StatusForbidden {
				t.Fatalf("test case #%d. middleware failed reject a non-matching Referer header: got %v want %v",
					i, rr.Code, http.StatusForbidden)
			}
		}
	}
}

// TestExcludedPath checks that HTTPS requests with a Referer that does not
// match the request URL skips CSRF validation if the path is excempt from
// CSRF checks.
func TestExcludedPath(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey, ExcludePaths("/excluded"))(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/excluded", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://golang.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to accept an excluded path: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

// TestExcludedPath checks that HTTPS requests with a Referer that does not
// match the request URL skips CSRF validation if the path is excempt from
// CSRF checks.
func TestRejectionWithExcludedPath(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey, ExcludePaths("/excluded"))(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "https://www.gorillatoolkit.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "https://www.gorillatoolkit.org/included", nil)
	if err != nil {
		t.Fatal(err)
	}

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://golang.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject on a non-excluded path: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}
