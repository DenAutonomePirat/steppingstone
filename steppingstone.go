package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/cas.v2"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v3"
)

type handleLogin struct{}
type handleLogout struct{}

var app = &Config{}

func main() {

	pathToConf := flag.String("p", "./conf.yml", "Path to yaml config file")
	debug := flag.Bool("d", false, "set to true for debug")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		log.Info("Setting loglevel to debug")
	}

	err := app.loadConfig(pathToConf)
	if err != nil {
		log.Fatalln(err.Error())
	}

	app.info()

	url, err := url.Parse(app.CasURL)
	if err != nil {
		log.Fatalln(err.Error())
	}

	client := cas.NewClient(&cas.Options{
		URL: url,
	})

	mux := http.NewServeMux()
	mux.Handle("/login", &handleLogin{})
	mux.Handle("/logout", &handleLogout{})
	server := &http.Server{
		Addr:    app.ServerAddr,
		Handler: client.Handle(mux),
	}

	log.Fatal(server.ListenAndServeTLS(app.HTTPSCertPath, app.HTTPSKeyPath))
}

func (h *handleLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debugln("Redirecting to logout")
	cas.RedirectToLogout(w, r)
}

func (h *handleLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Get tokens as array

	tokens, ok := r.URL.Query()["token"]

	if !ok || len(tokens[0]) < 1 {
		http.Error(w, "No token", http.StatusBadRequest)
		log.Info("No token")
		return
	}

	//select the first
	tokenString := tokens[0]

	log.Debugf("Recieved token \n%s\n", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return app.internalPublicKey, nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Warnf("%s\n", err.Error())
		return
	}

	tokenPriv, err := jwt.ParseWithClaims(tokenString, &LeihsClaims{}, func(token *jwt.Token) (interface{}, error) {
		return app.internalPublicKey, nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Warnf("%s\n", err.Error())
		return
	}
	u := &url.URL{
		Host: "https",
	}
	if claims, ok := tokenPriv.Claims.(*LeihsClaims); ok && tokenPriv.Valid {
		if !cas.IsAuthenticated(r) {
			cas.RedirectToLogin(w, r)
			return
		}
		if claims.Email == cas.Username(r) {

			u, err = u.Parse(claims.ServerBaseURL + claims.Path)
			if err != nil {
				fmt.Println(err.Error())
			}

			ackClaims := &LeihsClaims{
				Email:              cas.Username(r),
				Succes:             true,
				SignInRequestToken: token.Raw,
			}

			ackToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

			ackToken.Claims = ackClaims

			t, err := ackToken.SignedString(app.externalPrivateKey)
			log.Debugf("token for leihs\n%s\n", t)
			if err != nil {
				log.Warn(err.Error())
			}
			params := url.Values{}
			params.Add("token", t)
			u.RawQuery = params.Encode()

		} else {
			http.Error(w, "Please use same credentials", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Debugf("redirecting to %s\n", u.String())
	http.Redirect(w, r, u.String(), http.StatusFound)

}

// getEnv gets a environment variable panics if not set
func getEnv(key string) string {

	val, ok := os.LookupEnv(key)
	if !ok {
		panic(fmt.Sprintf("%s not set\n", key))
	} else {

		return val
	}
}

// LeihsClaims ....
type LeihsClaims struct {
	Email              string `json:"email,omitempty"`
	Login              string `json:"login,omitempty"`
	OrgID              string `json:"org_id,omitempty"`
	Exp                int64  `json:"exp,omitempty"`
	Iat                int64  `json:"iat,omitempty"`
	ServerBaseURL      string `json:"server_base_url,omitempty"`
	ReturnTo           string `json:"return_to,omitempty"`
	Path               string `json:"path,omitempty"`
	SignInRequestToken string `json:"sign_in_request_token,omitempty"`
	Succes             bool   `json:"success,omitempty"`
	jwt.StandardClaims
}

//Config ...
type Config struct {
	LeihsURL               string `yaml:"leihsurl"`
	CasURL                 string `yaml:"casurl"`
	ServerAddr             string `yaml:"server_addr"`
	ExpernalPrivateKeyPath string `yaml:"external_private_key_path"`
	InternalPublicKeyPath  string `yaml:"internal_public_key_path"`
	HTTPSCertPath          string `yaml:"https_cert_path"`
	HTTPSKeyPath           string `yaml:"https_key_path"`
	internalPublicKey      *ecdsa.PublicKey
	externalPrivateKey     *ecdsa.PrivateKey
}

func (config *Config) info() {
	s, _ := yaml.Marshal(app)
	log.Infof("\n%s\n", s)
}
func (config *Config) loadConfig(path *string) (err error) {
	file, err := os.Open(*path)
	if err != nil {
		c := Config{
			InternalPublicKeyPath:  "./keys/internal_public_key.pem",
			ExpernalPrivateKeyPath: "./keys/external_key_pair.pem",
			HTTPSCertPath:          "/etc/letsencrypt/live/{{.LeihsUrl}}/cert.pem",
			HTTPSKeyPath:           "/etc/letsencrypt/live/{{.LeihsUrl}}/privkey.pem",
		}
		file, err := os.Create(*path)
		if err != nil {
			log.Panic(fmt.Sprint(err.Error()))
		}
		defer file.Close()
		e := yaml.NewEncoder(file)
		err = e.Encode(&c)
		if err != nil {
			return err
		}
		return err
	}
	defer file.Close()

	data := yaml.NewDecoder(file)

	if err := data.Decode(&config); err != nil {
		return err
	}
	if strings.Contains(config.HTTPSCertPath, "{{.LeihsUrl}}") {
		u, _ := url.Parse(config.LeihsURL)
		config.HTTPSCertPath = strings.ReplaceAll(config.HTTPSCertPath, "{{.LeihsUrl}}", u.Host)
	}

	if strings.Contains(config.HTTPSKeyPath, "{{.LeihsUrl}}") {
		u, _ := url.Parse(config.LeihsURL)
		config.HTTPSKeyPath = strings.ReplaceAll(config.HTTPSKeyPath, "{{.LeihsUrl}}", u.Host)
	}

	k, err := ioutil.ReadFile(app.InternalPublicKeyPath)
	if err != nil {
		return err
	}

	app.internalPublicKey, err = jwt.ParseECPublicKeyFromPEM(k)
	if err != nil {
		return err
	}

	k, err = ioutil.ReadFile(app.ExpernalPrivateKeyPath)
	if err != nil {
		return err
	}

	app.externalPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(k)
	if err != nil {
		return err
	}

	return nil

}
