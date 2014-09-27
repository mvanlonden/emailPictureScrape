package main

import (
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"code.google.com/p/goauth2/oauth"
	gmail "code.google.com/p/google-api-go-client/gmail/v1"

	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"

	// Set by --clientid or --clientid_file
)

var config = &oauth.Config{
	ClientId:     "",
	ClientSecret: "",                       // Set by --secret or --secret_file
	Scope:        gmail.MailGoogleComScope, // filled in per-API
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
}

var debug = false

func main() {
	client := getOAuthClient(config)

	var counter = 0

	svc, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to create Gmail service: %v", err)
	}

	pageToken := ""

	t := time.Now()

	//subtract 1 week
	year, month, day := t.Add(-1 * 24 * time.Hour).Date()

	timeAgo := strconv.Itoa(year) + "/" + strconv.Itoa(int(month)) + "/" + strconv.Itoa(day)

	fmt.Println(timeAgo)

	req := svc.Users.Messages.List("me").Q("to:(newyork-all@ideo.com) has:attachment after:" + timeAgo)

	if pageToken != "" {
		req.PageToken(pageToken)
	}
	r, err := req.Do()
	if err != nil {
		log.Fatalf("Unable to retrieve messages: %v", err)
	}

	log.Printf("Processing %v messages...\n", len(r.Messages))
	for _, m := range r.Messages {
		msg, err := svc.Users.Messages.Get("me", m.Id).Do()
		// msgService := svc.Users.Messages.Get("me", m.Id)
		for _, part := range msg.Payload.Parts {
			fmt.Println(part.Filename)
			fmt.Println(part.Body.AttachmentId)
			// fmt.Println(json.NewDecoder(msg.Payload.Parts).Decode())
			filename := part.Filename
			if strings.Contains(strings.ToLower(filename), ".jpeg") || strings.Contains(strings.ToLower(filename), ".jpg") || strings.Contains(strings.ToLower(filename), ".png") {
				attach, err := svc.Users.Messages.Attachments.Get("me", msg.Id, part.Body.AttachmentId).Do()
				// fmt.Println(attach.Data)
				data, err := base64.URLEncoding.DecodeString(attach.Data)
				if err != nil {
					fmt.Println("error:", err)
					return
				}
				fmt.Println(len(data))
				err = ioutil.WriteFile("./pictures/"+strconv.Itoa(counter)+filename, data, 0644)
				counter++
				if err != nil {
					panic(err)
				}
			}
		}
		if err != nil {
			log.Fatalf("Unable to retrieve message %v: %v", m.Id, err)
		}

	}
}

func getOAuthClient(config *oauth.Config) *http.Client {
	cacheFile := tokenCacheFile(config)
	token, err := tokenFromFile(cacheFile)
	if err != nil {
		token = tokenFromWeb(config)
		saveToken(cacheFile, token)
	} else {
		log.Printf("Using cached token %#v from %q", token, cacheFile)
	}

	t := &oauth.Transport{
		Token:     token,
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	return t.Client()
}

func tokenCacheFile(config *oauth.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientId))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(config.Scope))
	fn := fmt.Sprintf("go-api-demo-tok%v", hash.Sum32())
	return filepath.Join(osUserCacheDir(), url.QueryEscape(fn))
}

func tokenFromFile(file string) (*oauth.Token, error) {
	return nil, errors.New("--cachetoken is false")
}

func osUserCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches")
	case "linux", "freebsd":
		return filepath.Join(os.Getenv("HOME"), ".cache")
	}
	log.Printf("TODO: osUserCacheDir on GOOS %q", runtime.GOOS)
	return "."
}

func tokenFromWeb(config *oauth.Config) *oauth.Token {
	ch := make(chan string)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			http.Error(rw, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			log.Printf("State doesn't match: req = %#v", req)
			http.Error(rw, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
			rw.(http.Flusher).Flush()
			ch <- code
			return
		}
		log.Printf("no code")
		http.Error(rw, "", 500)
	}))
	defer ts.Close()

	config.RedirectURL = ts.URL
	authUrl := config.AuthCodeURL(randState)
	go openUrl(authUrl)
	log.Printf("Authorize this app at: %s", authUrl)
	code := <-ch
	log.Printf("Got code: %s", code)

	t := &oauth.Transport{
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	_, err := t.Exchange(code)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}
	return t.Token
}

func openUrl(url string) {
	try := []string{"xdg-open", "google-chrome", "open"}
	for _, bin := range try {
		err := exec.Command(bin, url).Run()
		if err == nil {
			return
		}
	}
	log.Printf("Error opening URL in browser.")
}

func saveToken(file string, token *oauth.Token) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("Warning: failed to cache oauth token: %v", err)
		return
	}
	defer f.Close()
	gob.NewEncoder(f).Encode(token)
}

func condDebugTransport(rt http.RoundTripper) http.RoundTripper {
	return rt
}
