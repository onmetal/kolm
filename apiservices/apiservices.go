// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiservices

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/yaml"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

type RenderOptions struct {
	Paths              []string
	ErrorIfPathMissing bool
}

// Render iterates through options.Paths and extract all APIService files.
func Render(options RenderOptions) ([]*apiregistrationv1.APIService, error) {
	var (
		err   error
		info  os.FileInfo
		files []os.FileInfo
	)

	type GVKN struct {
		GVK  schema.GroupVersionKind
		Name string
	}

	apiServices := make(map[GVKN]*apiregistrationv1.APIService)

	for _, path := range options.Paths {
		var filePath = path

		// Return the error if ErrorIfPathMissing exists
		if info, err = os.Stat(path); os.IsNotExist(err) {
			if options.ErrorIfPathMissing {
				return nil, err
			}
			continue
		}

		if !info.IsDir() {
			filePath, files = filepath.Dir(path), []os.FileInfo{info}
		} else {
			dirEntries, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}

			files = make([]os.FileInfo, 0, len(dirEntries))
			for _, dirEntry := range dirEntries {
				file, err := dirEntry.Info()
				if err != nil {
					return nil, err
				}

				files = append(files, file)
			}
		}

		apiServiceList, err := readAPIServices(filePath, files)
		if err != nil {
			return nil, err
		}

		for i, apiService := range apiServiceList {
			gvkn := GVKN{GVK: apiService.GroupVersionKind(), Name: apiService.GetName()}
			if _, found := apiServices[gvkn]; found {
				// Currently, we only print a log when there are duplicates. We may want to error out if that makes more sense.
				return nil, fmt.Errorf("there are more than one APIService definitions with the same <Group, Version, Kind, GetName> %s", gvkn)
			}
			// We always use the APIService definition that we found last.
			apiServices[gvkn] = apiServiceList[i]
		}
	}

	// Converting map to a list to return
	var res []*apiregistrationv1.APIService
	for _, obj := range apiServices {
		res = append(res, obj)
	}
	return res, nil
}

// readAPIServices reads the CRDs from files and Unmarshals them into structs.
func readAPIServices(basePath string, files []os.FileInfo) ([]*apiregistrationv1.APIService, error) {
	var apiServices []*apiregistrationv1.APIService

	// White list the file extensions that may contain k8s manifests
	exts := sets.NewString(".json", ".yaml", ".yml")

	for _, file := range files {
		// Only parse allowlisted file types
		if !exts.Has(filepath.Ext(file.Name())) {
			continue
		}

		// Unmarshal APIServices from file into structs
		docs, err := readDocuments(filepath.Join(basePath, file.Name()))
		if err != nil {
			return nil, err
		}

		for _, doc := range docs {
			apiService := &apiregistrationv1.APIService{}
			if err = yaml.Unmarshal(doc, apiService); err != nil {
				return nil, err
			}

			if apiService.Kind != "APIService" || apiService.Spec.Group == "" || apiService.Spec.Version == "" {
				continue
			}
			apiServices = append(apiServices, apiService)
		}
	}
	return apiServices, nil
}

// readDocuments reads documents from file.
func readDocuments(fp string) ([][]byte, error) {
	b, err := os.ReadFile(fp) //nolint:gosec
	if err != nil {
		return nil, err
	}

	var docs [][]byte
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(b)))
	for {
		// Read document
		doc, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		docs = append(docs, doc)
	}

	return docs, nil
}
