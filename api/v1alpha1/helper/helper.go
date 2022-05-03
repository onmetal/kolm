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

package helper

import (
	"os"

	"github.com/onmetal/kolm/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	json2 "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	Scheme *runtime.Scheme
	Codec  runtime.Codec
)

func init() {
	Scheme = runtime.NewScheme()
	utilruntime.Must(v1alpha1.AddToScheme(Scheme))
	yamlSerializer := json2.NewSerializerWithOptions(json2.DefaultMetaFactory, Scheme, Scheme, json2.SerializerOptions{
		Yaml: true,
	})
	Codec = versioning.NewDefaultingCodecForScheme(
		Scheme,
		yamlSerializer,
		yamlSerializer,
		v1alpha1.GroupVersion,
		v1alpha1.GroupVersion,
	)
}

func ReadAPI(data []byte) (*v1alpha1.API, error) {
	var api v1alpha1.API
	defaults := v1alpha1.GroupVersion.WithKind(v1alpha1.APIKind)
	if _, _, err := Codec.Decode(data, &defaults, &api); err != nil {
		return nil, err
	}
	return &api, nil
}

func ReadAPIFile(filename string) (*v1alpha1.API, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return ReadAPI(data)
}

func WriteAPI(api *v1alpha1.API) ([]byte, error) {
	return runtime.Encode(Codec, api)
}

func WriteAPIFile(api *v1alpha1.API, filename string) error {
	data, err := WriteAPI(api)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}
