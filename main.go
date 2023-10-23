package main

import (
	"bufio"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
	"fmt"

	"github.com/fatih/color"
	"github.com/git-lfs/go-netrc/netrc"
	"github.com/theckman/yacspin"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

// Time before MFA step times out
const MFA_TIMEOUT = 30

var cfg = yacspin.Config{
	Frequency:         100 * time.Millisecond,
	CharSet:           yacspin.CharSets[59],
	Suffix:            "AWS SSO Signing in: ",
	SuffixAutoColon:   false,
	Message:           "",
	StopCharacter:     "✓",
	StopFailCharacter: "✗",
	StopMessage:       "Logged in successfully",
	StopFailMessage:   "Log in failed",
	StopColors:        []string{"fgGreen"},
}

var spinner, _ = yacspin.New(cfg)

func main() {
	spinner.Start()

	// get sso url from stdin
	url := getURL()
	// start aws sso login
	ssoLogin(url)

	spinner.Stop()
	time.Sleep(1 * time.Second)
}

// returns sso url from stdin.
func getURL() string {
	spinner.Message("reading url from stdin")

	scanner := bufio.NewScanner(os.Stdin)
	url := ""
	for url == "" {
		scanner.Scan()
		t := scanner.Text()
		r, _ := regexp.Compile("^https.*user_code=([A-Z]{4}-?){2}")

		if r.MatchString(t) {
			url = t
		}
	}

	return url
}

// get aws credentials from netrc file
func getCredentials() (string, string, string) {
	spinner.Message("fetching credentials from .netrc")

	usr, _ := user.Current()
	f, err := netrc.ParseFile(filepath.Join(usr.HomeDir, ".netrc"))
	if err != nil {
		panic(".netrc file not found in HOME directory")
	}

	username := f.FindMachine("headless-sso", "").Login
	passphrase := f.FindMachine("headless-sso", "").Password
	secret := f.FindMachine("headless-sso", "").Account

	return username, passphrase, secret
}

// login with hardware MFA
func ssoLogin(url string) {
	username, passphrase,secret  := getCredentials()
	spinner.Message(color.MagentaString("init headless-browser \n"))
	spinner.Pause()

	browser := rod.New().MustConnect().Trace(true)
	loadCookies(*browser)
	defer browser.MustClose()

	err := rod.Try(func() {
		page := browser.MustPage(url)

		// authorize
		spinner.Unpause()
		spinner.Message("logging in")
		page.MustElementR("button", "Confirm and continue").MustClick()

		// sign-in
		page.Race().ElementR("label","Username").MustHandle(func(e *rod.Element) {
			page.MustElement("#awsui-input-0").MustInput(username).MustType(input.Enter)
			page.MustElement("#awsui-input-1").MustInput(passphrase).MustType(input.Enter)
			mfa(*page, secret)
			page.MustWaitLoad().MustElementR("button", "Allow").MustClick()
		}).Element("#cli_login_button").MustHandle(func(e *rod.Element) {
			e.MustWaitLoad().MustElementR("button", "Allow").MustClick()
		}).MustDo()

		// success page
		page.MustElement(".awsui-signin-success")
		time.Sleep(500 * time.Millisecond)

		saveCookies(*browser)
	})

	if errors.Is(err, context.DeadlineExceeded) {
		panic("Timed out waiting for MFA")
	} else if err != nil {
		panic(err.Error())
	}
}

func generateTOTP(secretKey string, timestamp int64) uint32 {
	base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretKey = strings.ToUpper(strings.TrimSpace(secretKey))
	secretBytes, _ := base32Decoder.DecodeString(secretKey)

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp) / 30)

	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(timeBytes)
	h := hash.Sum(nil)
	offset := h[len(h)-1] & 0x0F
	truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

	return truncatedHash % 1_000_000
}

// load MFA Code
func mfa(page rod.Page, secret string) {
	now := time.Now().Unix()
	totpCode := generateTOTP(secret, now)
	var tocken = fmt.Sprintf("%06d",totpCode)
	spinner.Message(tocken)
	page.MustElement("#awsui-input-2").MustInput(tocken).MustType(input.Enter)
	spinner.Message(color.YellowString("filling MFA"))
}

// load cookies
func loadCookies(browser rod.Browser) {
	spinner.Message("loading cookies")
	dirname, err := os.UserHomeDir()
	if err != nil {
		error(err.Error())
	}

	data, _ := os.ReadFile(dirname + "/.headless-sso")
	sEnc, _ := b64.StdEncoding.DecodeString(string(data))
	var cookie *proto.NetworkCookie
	json.Unmarshal(sEnc, &cookie)

	if cookie != nil {
		browser.MustSetCookies(cookie)
	}
}

// save authn cookie
func saveCookies(browser rod.Browser) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		error(err.Error())
	}

	cookies := (browser.MustGetCookies())

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			err = os.WriteFile(dirname+"/.headless-sso", []byte(sEnc), 0644)

			if err != nil {
				error("Failed to save x-amz-sso_authn cookie")
			}
			break
		}
	}
}

// print error message and exit
func panic(errorMsg string) {
	red := color.New(color.FgRed).SprintFunc()
	spinner.StopFailMessage(red("Login failed error - " + errorMsg))
	spinner.StopFail()
	os.Exit(1)
}

// print error message
func error(errorMsg string) {
	yellow := color.New(color.FgYellow).SprintFunc()
	spinner.Message("Warn: " + yellow(errorMsg))
}

