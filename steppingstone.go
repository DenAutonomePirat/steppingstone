package steppingstone

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"

	"gopkg.in/cas.v1"
	"gopkg.in/yaml.v2"
)

// Run runs
func (config *Config) Run() {
	log.Fatal(config.server.ListenAndServeTLS(config.HTTPSCertPath, config.HTTPSKeyPath))

}

type handleLogin struct {
	config *Config
}
type handleLogout struct {
	config *Config
}

// Token ...
type Token struct {
	jwt.Token
}

func (config *Config) leihsPublicKey(token *jwt.Token) (key interface{}, err error) {
	return key, err
}

//ParseToken ...
func (config *Config) ParseToken(tokenString string) (token *Token, err error) {
	jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return config.internalPublicKey, nil
	})
	return nil, err
}

// ParseTokenWithClaims ...
func (config *Config) ParseTokenWithClaims(tokenString string) (token *Token, err error) {
	jwt.ParseWithClaims(tokenString, &LeihsClaims{}, func(token *jwt.Token) (interface{}, error) {
		return config.internalPublicKey, nil
	})
	return nil, err
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
	casClient              *cas.Client
	server                 *http.Server
	mux                    *http.ServeMux
}

// Info Prints parameters
func (config *Config) Info() {
	s, _ := yaml.Marshal(config)
	log.Infof("\n%s\n", s)
}

// LoadConfig accepts path as string ref.
func (config *Config) LoadConfig(path *string) (err error) {
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

	url, err := url.Parse(config.CasURL)
	if err != nil {
		log.Fatalln(err.Error())
	}

	config.casClient = cas.NewClient(&cas.Options{
		URL: url,
	})

	if strings.Contains(config.HTTPSCertPath, "{{.LeihsUrl}}") {
		u, _ := url.Parse(config.LeihsURL)
		config.HTTPSCertPath = strings.ReplaceAll(config.HTTPSCertPath, "{{.LeihsUrl}}", u.Host)
	}

	if strings.Contains(config.HTTPSKeyPath, "{{.LeihsUrl}}") {
		u, _ := url.Parse(config.LeihsURL)
		config.HTTPSKeyPath = strings.ReplaceAll(config.HTTPSKeyPath, "{{.LeihsUrl}}", u.Host)
	}

	k, err := ioutil.ReadFile(config.InternalPublicKeyPath)
	if err != nil {
		return err
	}

	config.internalPublicKey, err = jwt.ParseECPublicKeyFromPEM(k)
	if err != nil {
		return err
	}

	k, err = ioutil.ReadFile(config.ExpernalPrivateKeyPath)
	if err != nil {
		return err
	}

	config.externalPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(k)
	if err != nil {
		return err
	}

	config.mux = http.NewServeMux()
	config.mux.Handle("/login", &handleLogin{
		config: config,
	})
	config.mux.Handle("/logout", &handleLogout{
		config: config,
	})
	config.server = &http.Server{
		Addr:    config.ServerAddr,
		Handler: config.casClient.Handle(config.mux),
	}
	return nil

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
		return h.config.internalPublicKey, nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Warnf("%s\n", err.Error())
		return
	}

	tokenPriv, err := jwt.ParseWithClaims(tokenString, &LeihsClaims{}, func(token *jwt.Token) (interface{}, error) {
		return h.config.internalPublicKey, nil
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

			t, err := ackToken.SignedString(h.config.externalPrivateKey)
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
