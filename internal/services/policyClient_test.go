package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type test struct {
	Test string
}

func TestPolicyClientWithObject(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		var post map[string]interface{}

		derr := json.NewDecoder(r.Body).Decode(&post)
		if derr != nil {
			panic(derr)
		}

		if post["Test"] != "Bla" {
			t.Error()
		}

		back := test{
			Test: "return",
		}

		b, err := json.Marshal(back)

		if err != nil {
			t.Error()
		}

		w.Write(b)
	}))

	o := test{
		Test: "Bla",
	}

	res, err := GetPolicyResult(o, srv.URL)

	if err != nil {
		t.Error()
	}

	if res["Test"] != "return" {
		t.Error()
	}

}
