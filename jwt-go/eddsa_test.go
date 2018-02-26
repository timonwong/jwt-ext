package jwtext

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/ed25519"
)

var eddsaTestData = []struct {
	name        string
	keys        map[string]string
	tokenString string
	alg         string
	valid       bool
}{
	{
		"Basic EdDSA",
		map[string]string{
			"private": "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=",
			"public":  "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		},
		"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
		algName,
		true,
	},
}

func TestEdDSAVerify(t *testing.T) {
	for _, data := range eddsaTestData {
		var err error

		key, _ := base64.StdEncoding.DecodeString(data.keys["public"])
		var edKey ed25519.PublicKey = key

		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)
		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], edKey)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestEdDSASign(t *testing.T) {
	for _, data := range eddsaTestData {
		pubkey, _ := base64.StdEncoding.DecodeString(data.keys["public"])
		key, _ := base64.StdEncoding.DecodeString(data.keys["private"])
		var edKey ed25519.PrivateKey = append(key, pubkey...)

		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), edKey)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			if sig != parts[2] {
				t.Errorf("[%v] Incorrect signature\nbefore:\n%v\nafter:\n%v", data.name, parts[2], sig)
			}
		}
	}
}
