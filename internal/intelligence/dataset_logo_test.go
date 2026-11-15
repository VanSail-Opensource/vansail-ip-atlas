package intelligence

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDatasetLogoSharedBytesAndSafeLocalFile(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/contracts/dataset-logos-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version int `json:"schema_version"`
		Cases   []struct {
			Name, Base64, SHA256 string
			Valid                bool
		}
	}
	if json.Unmarshal(data, &corpus) != nil || corpus.Version != 1 {
		t.Fatal("invalid logo corpus")
	}
	for _, row := range corpus.Cases {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(row.Base64)
			if err != nil {
				t.Fatal(err)
			}
			if got := ValidateDatasetLogoBytes(raw, row.SHA256) == nil; got != row.Valid {
				t.Fatalf("valid=%v want%v", got, row.Valid)
			}
			root := t.TempDir()
			dir := filepath.Join(root, "fixtures", "source-certification", "logos")
			if err = os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			logo := &DatasetLogo{Path: "/_atlas/legal/" + row.SHA256 + ".png", SHA256: row.SHA256, Alt: "Synthetic publisher"}
			if ValidateDatasetLogoFile(root, logo) == nil {
				t.Fatal("missing file accepted")
			}
			if err = os.WriteFile(filepath.Join(dir, row.SHA256+".png"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if got := ValidateDatasetLogoFile(root, logo) == nil; got != row.Valid {
				t.Fatal("local logo mismatch")
			}
		})
	}
}
