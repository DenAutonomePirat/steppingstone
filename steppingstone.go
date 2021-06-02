package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"

	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/cas.v2"

	"github.com/denautonomepirat/leihs"
	"github.com/dgrijalva/jwt-go"

	"gopkg.in/yaml.v3"
)

type handleLogin struct{}
type handleLogout struct{}

var app = &Config{}

func main() {

	pathToConf := flag.String("p", "./conf.yml", "Path to yaml config file")
	Insecure := flag.Bool("insecure", false, "set to true for skipping verify")
	flag.Parse()

	if *Insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	err := app.loadConfig(pathToConf)
	if err != nil {
		log.Fatalln(err.Error())
	}

	app.info()

	app.leihs = leihs.NewLeihs(&leihs.Config{
		Token:    app.LeihsToken,
		LeihsURL: app.LeihsURL,
	})

	as, err := app.leihs.AuthenticationSystemByName(app.AuthenticationSystem.Name)

	if err != nil {
		log.Warn(err)
		as = app.AuthenticationSystem
		as.InternalPrivateKey = encodePrivate(app.internalPrivateKey)
		as.InternalPublicKey = encodePublic(app.internalPrivateKey)
		as.ExternalPublicKey = encodePublic(app.externalPrivateKey)
		as.CreatedAt = time.Now()
		as.UpdatedAt = time.Now()
		err = app.leihs.AddAuthenticationSystem(as)
		if err != nil {
			log.Warn(err)
		}
	}
	//Set app.auth.. for later ref.
	app.authenticationSystem, err = app.leihs.AuthenticationSystemByName(app.AuthenticationSystem.Name)
	if err != nil {
		log.Fatalf("Failed to set up authenticationSystem: %s\n", err.Error())
	}
	g := &leihs.Group{
		Name:        app.authenticationSystem.Name,
		Description: "Authentication group for system",
	}
	err = app.leihs.AddGroup(g)
	if err != nil {
		log.Warn(err)
	}
	app.group, err = app.leihs.GroupByName(app.authenticationSystem.Name)
	if err != nil {
		log.Fatalf("Failed to set up group: %s\n", err.Error())
	}

	err = app.leihs.AddToAuthenticationSystem(app.group, app.authenticationSystem)
	if err != nil {
		log.Fatalf("Failed to bind authentication system to group: %s\n", err.Error())
	}

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
		Addr:    app.serverURL.Host,
		Handler: client.Handle(mux),
	}
	if app.serverURL.Scheme == "https" {
		log.Fatal(server.ListenAndServeTLS(app.HTTPSCertPath, app.HTTPSKeyPath))
	} else {
		log.Fatal(server.ListenAndServe())

	}
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
		log.Debug("No token")
		return
	}

	//select the first
	tokenString := tokens[0]

	log.Debugf("Recieved token: \"%s\"\n", tokenString)

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
		log.Warnf("Error on incomming %s\n", err.Error())
		return
	}
	u := &url.URL{}
	if claims, ok := tokenPriv.Claims.(*LeihsClaims); ok && tokenPriv.Valid {
		if !cas.IsAuthenticated(r) {
			cas.RedirectToLogin(w, r)
			return
		}
		//check if cas user and leihs user matches otherwise leihs will dead-end the user exp.
		if claims.Email == cas.Username(r) {
			//check if user exists otherwise upsert with minimal user
			user, err := app.leihs.FindUser(claims.Email)
			if err != nil {
				log.Debug(err.Error())

				user = &leihs.User{
					Email:                 claims.Email,
					AccountEnabled:        true,
					PasswordSignInEnabled: false,
					UpdatedAt:             time.Now(),
					CreatedAt:             time.Now(),
				}

				_, err = app.leihs.AddUser(user)
				if err != nil {
					log.Warn(err)
				}
				user, err = app.leihs.FindUser(claims.Email)

			}

			err = app.leihs.AddToGroup(user, app.group)
			if err != nil {
				log.Warn(err.Error())
			}

			u, err = u.Parse(claims.ServerBaseURL + claims.Path)
			if err != nil {
				log.Warn(err.Error())
			}
			u.Scheme = "https"

			ackClaims := &LeihsClaims{
				Email:              cas.Username(r),
				Succes:             true,
				SignInRequestToken: token.Raw,
			}

			ackToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

			ackToken.Claims = ackClaims

			t, err := ackToken.SignedString(app.externalPrivateKey)
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
	LeihsURL               string                      `yaml:"leihsurl"`
	LeihsToken             string                      `yaml:"leihstoken"`
	CasURL                 string                      `yaml:"casurl"`
	ServerAddr             string                      `yaml:"server_addr"`
	MailWildcard           string                      `yaml:"mail_wildcard"`
	ExternalAuthURL        string                      `yaml:"external_authentication_url"`
	ExternalPrivateKeyPath string                      `yaml:"external_private_key_path"`
	InternalPrivateKeyPath string                      `yaml:"internal_private_key_path"`
	InternalPublicKeyPath  string                      `yaml:"internal_public_key_path"`
	HTTPSCertPath          string                      `yaml:"https_cert_path"`
	HTTPSKeyPath           string                      `yaml:"https_key_path"`
	AuthenticationSystem   *leihs.AuthenticationSystem `yaml:"authentication_system"`
	CustomLog              string                      `yaml:"custom_log"`
	serverURL              *url.URL
	authenticationSystem   *leihs.AuthenticationSystem
	group                  *leihs.Group
	internalPrivateKey     *ecdsa.PrivateKey
	externalPrivateKey     *ecdsa.PrivateKey
	internalPublicKey      *ecdsa.PublicKey
	leihs                  *leihs.Leihs
}

func (config *Config) info() {
	s, _ := yaml.Marshal(app)
	log.Debugf("\n%s\n", s)
}
func (config *Config) loadConfig(path *string) (err error) {
	file, err := os.Open(*path)
	if err != nil {
		c := Config{
			InternalPrivateKeyPath: "./keys/internal_key_pair.pem",
			ExternalPrivateKeyPath: "./keys/external_key_pair.pem",
			HTTPSCertPath:          "/etc/letsencrypt/live/{{.LeihsUrl}}/cert.pem",
			HTTPSKeyPath:           "/etc/letsencrypt/live/{{.LeihsUrl}}/privkey.pem",
			AuthenticationSystem:   &leihs.AuthenticationSystem{},
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
		u, err := url.Parse(config.LeihsURL)
		if err != nil {
			log.Fatalln(err)
		}

		config.HTTPSCertPath = strings.ReplaceAll(config.HTTPSCertPath, "{{.LeihsUrl}}", u.Host)
	}

	if strings.Contains(config.HTTPSKeyPath, "{{.LeihsUrl}}") {
		u, err := url.Parse(config.LeihsURL)
		if err != nil {
			log.Fatalln(err)
		}
		config.HTTPSKeyPath = strings.ReplaceAll(config.HTTPSKeyPath, "{{.LeihsUrl}}", u.Host)
	}

	k, err := ioutil.ReadFile(app.InternalPrivateKeyPath)
	if err != nil {
		return err
	}

	app.internalPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(k)
	if err != nil {
		return err
	}
	k, err = ioutil.ReadFile(app.InternalPublicKeyPath)
	if err != nil {
		return err
	}

	app.internalPublicKey, err = jwt.ParseECPublicKeyFromPEM(k)
	if err != nil {
		return err
	}

	k, err = ioutil.ReadFile(app.ExternalPrivateKeyPath)
	if err != nil {
		return err
	}

	app.externalPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(k)
	if err != nil {
		return err
	}

	app.serverURL, err = url.Parse(app.ServerAddr)
	if err != nil {
		return err
	}

	return nil
}

// encode returns private/public keys as pem encoded strings
func encodePrivate(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}

func encodePublic(privateKey *ecdsa.PrivateKey) string {

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub)
}

/*
func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}
*/
