package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/cas.v2"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v3"
)

//Config ...
type Config struct {
	LeihsURL string `yaml:"leihsurl"`
	CasURL   string `yaml:"casurl"`
}

// LeihsClaims ....
type LeihsClaims struct {
	Email              string `json:"email"`
	Login              string `json:"login"`
	OrgID              string `json:"org_id"`
	Exp                int64  `json:"exp"`
	Iat                int64  `json:"iat"`
	ServerBaseURL      string `json:"server_base_url"`
	ReturnTo           string `json:"return_to"`
	Path               string `json:"path"`
	SignInRequestToken string `json:"sign_in_request_token"`
	jwt.StandardClaims
}

func newConfig(path string) (config *Config, err error) {
	file, err := os.Open(path)
	if err != nil {

		//create empty conf
		c := Config{}
		file, err := os.Create(path)
		if err != nil {
			panic(fmt.Sprint(err.Error()))
		}
		defer file.Close()
		e := yaml.NewEncoder(file)
		err = e.Encode(&c)
		if err != nil {
			return nil, err
		}
		return nil, err
	}
	defer file.Close()

	data := yaml.NewDecoder(file)

	if err := data.Decode(&config); err != nil {
		return nil, err
	}
	return config, nil
}

type myHandler struct{}

//MyHandler ...
var MyHandler = &myHandler{}
var key *ecdsa.PublicKey
var signingKey *ecdsa.PrivateKey

func main() {

	var pathToConf string
	flag.StringVar(&pathToConf, "-p", "./conf.yaml", "Path to yaml config file")

	flag.Parse()

	conf, err := newConfig(pathToConf)
	if err != nil {
		panic(fmt.Sprintf(err.Error()))
	}

	url, _ := url.Parse(conf.CasURL)
	client := cas.NewClient(&cas.Options{
		URL: url,
	})

	mux := http.NewServeMux()
	mux.Handle("/leihs/login", MyHandler)

	server := &http.Server{
		Addr:    ":443",
		Handler: client.Handle(mux),
	}

	internalPublicKey, err := ioutil.ReadFile("./keys/internal_public_key.pem")
	if err != nil {
		panic(err.Error())
	}

	key, _ = jwt.ParseECPublicKeyFromPEM(internalPublicKey)

	externalPrivateKey, err := ioutil.ReadFile("./keys/external_key_pair.pem")
	if err != nil {
		panic(err.Error())
	}
	signingKey, err = jwt.ParseECPrivateKeyFromPEM(externalPrivateKey)
	if err != nil {
		panic(err.Error())
	}
	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))

}

func (h *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Get token and strip
	tokenString := r.URL.Query()["token"][0]

	token, err := jwt.ParseWithClaims(tokenString, &LeihsClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil // key skal være env
	})

	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return
	}
	if token.Valid {
		u := &url.URL{
			Host: "https",
		}
		if claims, ok := token.Claims.(*LeihsClaims); ok && token.Valid {
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
					Iat:                time.Now().Unix(),
					Exp:                claims.Iat + 1000,
					SignInRequestToken: token.Raw,
				}
				ackToken := jwt.NewWithClaims(jwt.SigningMethodES256, ackClaims)
				t, err := ackToken.SignedString(signingKey)
				if err != nil {
					fmt.Println(err.Error())
				}

				params := url.Values{}
				params.Add("token", t)
				u.RawQuery = params.Encode()

			}

		} else {
			fmt.Println(err)
		}

		fmt.Printf("redirecting to %s\n", u.String())
		http.Redirect(w, r, u.String(), http.StatusFound)

	}
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
