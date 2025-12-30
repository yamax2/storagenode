package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed page.html
var pageHTML string

var (
	privateKey *rsa.PrivateKey
	keyID      string
	pageTmpl   *template.Template
)

type PageData struct {
	Token string
}

func main() {
	keyPath := flag.String("key", "", "path to RSA private key (PEM)")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("key path is required: -key <path>")
	}

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		log.Fatal("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}
	privateKey = key
	keyID = generateKeyID(&key.PublicKey)

	pageTmpl = template.Must(template.New("page").Parse(pageHTML))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		token, err := generateJWT(map[string]any{"method": "GET", "uri": "/service/start"})
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		pageTmpl.Execute(w, PageData{Token: token})
	})

	log.Println("Server starting on 0.0.0.0:8080")
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

func generateKeyID(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	hash := sha256.Sum256(der)

	return base64urlEncode(hash[:])[:16]
}

func generateJWT(payload map[string]any) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	}

	payload["exp"] = time.Now().Add(time.Hour).Unix()

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	signingInput := base64urlEncode(headerJSON) + "." + base64urlEncode(payloadJSON)

	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64urlEncode(signature), nil
}

func base64urlEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
