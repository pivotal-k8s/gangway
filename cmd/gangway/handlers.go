// Copyright © 2017 Heptio
// Copyright © 2017 Craig Tracey
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"text/template"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	templatesBase = "templates"
)

type userInfo struct {
	ClusterName  string
	Username     string
	Email        string
	IDToken      string
	RefreshToken string
	ClientID     string
	ClientSecret string
	IssuerURL    string
}

func serveTemplate(tmplFile string, data interface{}, w http.ResponseWriter) {

	templatePath := filepath.Join(templatesBase, tmplFile)
	templateData, err := Asset(templatePath)
	if err != nil {
		log.Errorf("Failed to find template asset: %s", tmplFile)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.New(tmplFile)
	tmpl, _ = tmpl.Parse(string(templateData))
	tmpl.ExecuteTemplate(w, tmplFile, data)
}

func loginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, "gangway")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		if session.Values["id_token"] == nil {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	serveTemplate("home.tmpl", nil, w)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, err := sessionStore.Get(r, "gangway")
	if err != nil {
		log.Errorf("Got an error in login: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience := oauth2.SetAuthURLParam("audience", cfg.Audience)
	url := oauth2Cfg.AuthCodeURL(state, audience)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cleanupSession(w, r)
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[cb] callback handler starting")

	// verify the state string
	state := r.URL.Query().Get("state")
	session, err := sessionStore.Get(r, "gangway")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[cb] got session: %#v", session)

	if state != session.Values["state"] {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	log.Printf("[cb] session is valid")

	// use the access code to retrieve a token
	code := r.URL.Query().Get("code")

	ctx := context.TODO()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	unsafeClient := &http.Client{Transport: tr}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, unsafeClient)

	token, err := oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[cb] got oauth token: %#v", token)

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["refresh_token"] = token.RefreshToken
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[cb] session saved: %#v", session)
	log.Printf("[cb] redirecting to /commandline")

	http.Redirect(w, r, "/commandline", http.StatusSeeOther)

	log.Printf("[cb] callback handler done")
}

func parseToken(idToken string) (*jwt.Token, error) {
	token, _ := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(cfg.ClientSecret), nil
	})
	return token, nil
}

func commandlineHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "gangway")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	log.Printf("got session: %#v", session)

	idToken, ok := session.Values["id_token"].(string)
	if !ok {
		//http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		cleanupSession(w, r)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("got idToken: %#v", idToken)

	refreshToken, ok := session.Values["refresh_token"].(string)
	if !ok {
		//http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		cleanupSession(w, r)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("got refreshToken: %#v", refreshToken)

	jwtToken, err := parseToken(idToken)
	if err != nil {
		http.Error(w, "Could not parse JWT", http.StatusInternalServerError)
		return
	}

	log.Printf("got jwtToken: %#v", jwtToken)

	claims := jwtToken.Claims.(jwt.MapClaims)

	log.Printf("got claims: %#v", claims)

	username, ok := claims[cfg.UsernameClaim].(string)
	if !ok {
		http.Error(w, "Could not parse Username claim", http.StatusInternalServerError)
		return
	}

	log.Printf("got username: %#v", username)

	email, ok := claims[cfg.EmailClaim].(string)
	if !ok {
		http.Error(w, "Could not parse Email claim", http.StatusInternalServerError)
		log.Println("email Handler")
		return
	}

	log.Printf("got email: %#v", email)

	issuerURL, ok := claims["iss"].(string)
	if !ok {
		http.Error(w, "Could not parse Issuer URL claim", http.StatusInternalServerError)
		return
	}

	log.Printf("got issuerURL: %#v", issuerURL)

	info := &userInfo{
		ClusterName:  cfg.ClusterName,
		Username:     username,
		Email:        email,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		IssuerURL:    issuerURL,
	}

	log.Printf("about to serve template with %#v", info)
	serveTemplate("commandline.tmpl", info, w)
	log.Printf("template successfully served")
}
