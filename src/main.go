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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type RedeploymentCommand struct {
	WorkDir  string   `yaml:"work_dir" json:"work_dir"`
	Commands []string `yaml:"commands" json:"commands"`
}

type Redeployment struct {
	RedeploymentCommand
	Results []Result `json:"results"`
	Done    bool     `json:"done"`
}

type Result struct {
	Output   string        `json:"output,omitempty"`
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration,omitempty"`
}

func (r *Redeployment) Run(id uuid.UUID, redeployments map[uuid.UUID]*Redeployment, mutex *sync.Mutex) {
	for _, command := range r.Commands {
		mutex.Lock()

		r.Results = append(r.Results, Result{
			Start:    time.Now(),
			Duration: 0,
		})

		mutex.Unlock()

		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = r.WorkDir
		err := cmd.Run()

		mutex.Lock()
		result := &r.Results[len(r.Results)-1]

		result.Duration = time.Now().Sub(result.Start)
		if err != nil {
			if err, ok := err.(*exec.ExitError); ok {
				result.Output = string(err.Stderr)
			} else {
				result.Output = "<could not run command>: " + err.Error()
			}
			mutex.Unlock()
			break
		}

		mutex.Unlock()
	}
	r.Done = true

	time.Sleep(time.Minute)

	delete(redeployments, id)
}

func GetRedeploymentStatus(redeployments map[uuid.UUID]*Redeployment, redeploymentsLock *sync.Mutex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redeploymentsLock.Lock()
		defer redeploymentsLock.Unlock()

		idBytes, err := hex.DecodeString(strings.Trim(r.URL.Path, "/"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("ID is not valid hex"))
			return
		}

		id, err := uuid.FromBytes(idBytes)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("ID is not of valid length"))
			return
		}

		redeployment, ok := redeployments[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("No redeployment found with ID"))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)

		json.NewEncoder(w).Encode(redeployment)
	})
}

func HandleWebhook(host string, addCommand func(RedeploymentCommand) uuid.UUID) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		var yamlFile map[string]map[string]RedeploymentCommand
		if err := yaml.Unmarshal(contents, &yamlFile); err != nil {
			log.Println("failed parsing config file:", err)
			return
		}

		sub, ok := yamlFile[body.Repository.Name]
		if !ok {
			log.Println(
				"WARNING: No deployment instructions for repository",
				body.Repository.Name,
			)
			return
		}

		command, ok := sub[body.Ref]
		if !ok {
			return
		}

		id := addCommand(command)
		idString := hex.EncodeToString(id[:])
		w.Write([]byte(fmt.Sprintf("https://%s/%s", host, idString)))
	})
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
	host := os.Getenv("HOST")

	if len(secretToken) < 16 {
		log.Fatalln("Secret token too short or not provided")
	}

	redeployments := make(map[uuid.UUID]*Redeployment)
	redeploymentsLock := new(sync.Mutex)

	addCommand := func(command RedeploymentCommand) uuid.UUID {
		redeploymentsLock.Lock()

		id, err := uuid.NewRandom()
		if err != nil {
			log.Fatalln(err)
		}
		redeployment := &Redeployment{
			RedeploymentCommand: command,
		}
		redeployments[id] = redeployment

		redeploymentsLock.Unlock()

		go redeployment.Run(id, redeployments, redeploymentsLock)

		return id
	}

	err := http.ListenAndServe(
		"127.0.0.1:7293",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				VerifySignature(secretToken, HandleWebhook(host, addCommand)).ServeHTTP(w, r)
			} else if r.Method == http.MethodGet {
				GetRedeploymentStatus(redeployments, redeploymentsLock).
					ServeHTTP(w, r)
			}
		}),
	)
	log.Fatalln(err)
}
