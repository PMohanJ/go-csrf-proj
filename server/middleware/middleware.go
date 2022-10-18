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
	fn := func(w http.ResponseWriter, r *http.Request) {

		// check if the user made req is autheticated or not by validating the
		// tokens
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In the auth section checking for authenticity!")

			// Get the cookies
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No auth Cookie")
				nullifyTokenCookies(&w, r)
				// http.Redirect(w, r, "/login", 302)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panic("Panic %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No refersh Cookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panic("Panic %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			// grad the csrf token
			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			// Now check the tokens for validity
			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attemp! JWT's not valid!")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Println("Err not nil, may be server side error")
					log.Panic("Panic %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}

			log.Println("Successfully recreated JWTs")

			w.Header().Set("Access-Control-Allow-Origin", "*")

			// everything is valid! And tokens have been refreshed if need-be
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)

		default:
			// Just redundant
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
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

				// set the cookies to these newly created jwt's
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)

		}

	case "/logout":
		// remove this user's ability to make requests
		nullifyTokenCookies(&w, r)
		// use 302 to force browser to make GET request
		http.Redirect(w, r, "/login", 302)

	case "/deleteUser":

	default:
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshToken, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		log.Panic("Panic: %+V", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	myJwt.RevokeRefreshToken(RefreshToken.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToke",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue(" n")
	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}

}
