package csrf_test

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/meplato/csrf"
)

func ExampleProtect() {
	var form = `
	<html>
	<head>
	<title>Sign Up!</title>
	</head>
	<body>
	<form method="POST" action="/signup/post" accept-charset="UTF-8">
	<input type="text" name="name">
	<input type="text" name="email">
	<!--
	The default template tag used by the CSRF middleware .
	This will be replaced with a hidden <input> field containing the
	masked CSRF token.
	-->
	{{ .csrfField }}
	<input type="submit" value="Sign up!">
	</form>
	</body>
	</html>
	`

	var t = template.Must(template.New("signup_form.tmpl").Parse(form))

	r := mux.NewRouter()

	r.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		// signup_form.tmpl just needs a {{ .csrfField }} template tag for
		// csrf.TemplateField to inject the CSRF token into. Easy!
		t.ExecuteTemplate(w, "signup_form.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		})
	})

	// All POST requests without a valid token will return HTTP 403 Forbidden.
	// We should also ensure that our mutating (non-idempotent) handler only
	// matches on POST requests. We can check that here, at the router level, or
	// within the handler itself via r.Method.
	r.HandleFunc("/signup/post", func(w http.ResponseWriter, r *http.Request) {
		// We can trust that requests making it this far have satisfied
		// our CSRF protection requirements.
		fmt.Fprintf(w, "%v\n", r.PostForm)
	}).Methods("POST")

	// Add the middleware to your router by wrapping it.
	http.ListenAndServe(":8000",
		csrf.Protect([]byte("32-byte-long-auth-key"))(r))
	// PS: Don't forget to pass csrf.Secure(false) if you're developing locally
	// over plain HTTP (just don't leave it on in production).
}

func ExampleTrustedOrigins() {
	r := mux.NewRouter()

	// Add the middleware to your router by wrapping it.
	csrfProtection := csrf.Protect([]byte("32-byte-long-auth-key"),
		// Allow requests from example.com and js.example.com
		csrf.TrustedOrigins([]string{"api.example.com", "js.example.com"}),
	)
	http.ListenAndServe(":8000", csrfProtection(r))
	// PS: Don't forget to pass csrf.Secure(false) if you're developing locally
	// over plain HTTP (just don't leave it on in production).
}

func ExampleTrustedOriginsCallback() {
	r := mux.NewRouter()

	// Add the middleware to your router by wrapping it.
	csrfProtection := csrf.Protect([]byte("32-byte-long-auth-key"),
		// Allow requests when callback returns true
		csrf.TrustedOriginsCallback(func(referer *url.URL, r *http.Request) bool {
			return referer.Host == "api.example.com" || referer.Host == "js.example.com"
		}),
	)
	http.ListenAndServe(":8000", csrfProtection(r))
	// PS: Don't forget to pass csrf.Secure(false) if you're developing locally
	// over plain HTTP (just don't leave it on in production).
}

func ExampleExcludePaths() {
	r := mux.NewRouter()

	// Add the middleware to your router by wrapping it.
	csrfProtection := csrf.Protect([]byte("32-byte-long-auth-key"),
		// Excempt /api and /healthz from CSRF protection
		csrf.ExcludePaths("/api", "/healthz"),
	)
	http.ListenAndServe(":8000", csrfProtection(r))
	// PS: Don't forget to pass csrf.Secure(false) if you're developing locally
	// over plain HTTP (just don't leave it on in production).
}
