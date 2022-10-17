package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/pmohanj/golang-csrf-project/db"
	"github.com/pmohanj/golang-csrf-project/server/middleware/myJwt"
	"github.com/pmohanj/golang-csrf-project/server/templates"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// this func to recover any panic calls and handler them, learn recover()

		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered! Panic: %+V", err)
				http.Error(w, "Internal Server Error", 500)
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)

}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.Response, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "logout", "/deleteUser":
		default:
		}
	}
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{CsrfSecret: csrfSecret, SecretMessage: "Hello Bro"})

	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{false, ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			// check to see if usernmae already exists or username is already taken
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				// create acc for this user
				role := "user"
				uuid, err := db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid: ", uuid)

				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewToken(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			// remove this user's ability to make requests
			w.WriteHeader(http.StatusMethodNotAllowed)
			// use 302 to force browser to make GET request
			http.Redirect(w, r, "/login", 302)
		}
	case "/logout":
		nullifyTokenCookies(w, r)
	case "/deleteUser":
	default:
	}
}

func nullifyTokenCookies(w http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshToken, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		log.Panic("Panic: %+V", refreshErr)
		http.Error(w, http.StatusText(500), 500)
	}

	myJwt.RevokeRefreshToken(RefreshToken.Value)
}

func setAuthAndRefreshCookies(w http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToke",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")
	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}

}
