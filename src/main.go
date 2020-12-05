package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
	"github.com/joho/godotenv"
)

type Config struct {
	WorkDir  string   `yaml:"work_dir"`
	Commands []string `yaml:"commands"`
}

func Handle(w http.ResponseWriter, r *http.Request) {
	// TODO: also receive merged pull requests?
	var body struct {
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
		Ref string `json:"ref"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Println("json decoding error:", err)
		return
	}

	contents, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Println("failed reading config file (config.yml):", err)
		return
	}

	var yamlFile map[string]map[string]Config
	if err := yaml.Unmarshal(contents, &yamlFile); err != nil {
		log.Println("failed parsing config file:", err)
		return
	}

	sub, ok := yamlFile[body.Repository.Name]
	if !ok {
		log.Println(
			"No deployment instructions for repository",
			body.Repository.Name,
		)
		return
	}

	config, ok := sub[body.Ref]
	if !ok {
		log.Println(
			"No deployment instructions for ref",
			body.Ref,
		)
		return
	}

	for _, command := range config.Commands {
		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = config.WorkDir
		err := cmd.Run()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if err, ok := err.(*exec.ExitError); ok {
				w.Write([]byte(fmt.Sprintf(
					"Deployment failed for %v %v!\nCommand: %v\nExit code: %v\nStderr:",
					body.Repository.Name,
					body.Ref,
					command,
					err.ProcessState.ExitCode(),
				)))
				w.Write(err.Stderr)
			} else {
				w.Write([]byte(fmt.Sprintf(
					"Deployment failed for %v %v!\nError: %s",
					body.Repository.Name,
					body.Ref,
					err,
				)))
			}
			break
		}
	}

}

func VerifySignature(SecretToken []byte, inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature := strings.TrimPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256=")

		h := hmac.New(sha256.New, SecretToken)
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}
		if err := r.Body.Close(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		h.Write(body)
		wantedSignature := hex.EncodeToString(h.Sum(nil))

		equal := subtle.ConstantTimeCompare(
			[]byte(wantedSignature),
			[]byte(receivedSignature),
		)
		if equal != 1 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Invalid signature"))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Error while reading .env")
	}

	secretToken := []byte(os.Getenv("SECRET_TOKEN"))

	if len(secretToken) < 16 {
		log.Fatalln("Secret token too short or not provided")
	}

	err := http.ListenAndServe(
		"127.0.0.1:7293",
		VerifySignature(
			secretToken,
			http.HandlerFunc(Handle),
		),
	)
	log.Fatalln(err)
}
