package sigma

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"gopkg.in/yaml.v3"
)

func TestParseConfig(t *testing.T) {
	err := filepath.Walk("./testdata/", func(path string, info os.FileInfo, err error) error {
		fmt.Println("path", path)
		if !strings.HasSuffix(path, ".config.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".config.yml"), func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseConfig(contents)
			if err != nil {
				t.Fatalf("error parsing config: %v", err)
			}

			cupaloy.New(cupaloy.SnapshotSubdirectory("testdata")).SnapshotT(t, rule)
		})
		t.Run(strings.TrimSuffix(filepath.Base(path), ".config.yaml")+"-remarshalled", func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseConfig(contents)
			if err != nil {
				t.Fatalf("error parsing config: %v", err)
			}

			reMarshalled, err := yaml.Marshal(rule)
			if err != nil {
				t.Fatalf("error remarshalling config: %v", err)
			}

			cupaloy.New(cupaloy.SnapshotSubdirectory("testdata")).SnapshotT(t, reMarshalled)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
