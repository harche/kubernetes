/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package versioned

import (
	"encoding/json"
	"fmt"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/kubectl/generate"
	"k8s.io/kubernetes/pkg/kubectl/util/hash"
)

// SecretForDecryptImageGeneratorV1 supports stable generation of a docker registry secret
type SecretForDecryptImageGeneratorV1 struct {
	// PrivateKeyMap abc (required) key is privatekey and value is corr. passwd
	//PrivateKeyMap map[string]string
	// Name of secret (required)
	Name string

	// PrivateKey abc
	PrivateKeyPasswds []string
	// FileSources to derive the secret from (optional)
	// FileSources []string
	// // Username for registry (required)
	// Username string
	// // Email for registry (optional)
	// Email string
	// // Password for registry (required)
	// Password string
	// // Server for registry (required)
	// Server string
	// AppendHash; if true, derive a hash from the Secret and append it to the name
	AppendHash bool
}

// Ensure it supports the generator pattern that uses parameter injection
var _ generate.Generator = &SecretForDecryptImageGeneratorV1{}

// Ensure it supports the generator pattern that uses parameters specified during construction
var _ generate.StructuredGenerator = &SecretForDecryptImageGeneratorV1{}

// Generate returns a secret using the specified parameters
func (s SecretForDecryptImageGeneratorV1) Generate(genericParams map[string]interface{}) (runtime.Object, error) {
	err := generate.ValidateParams(s.ParamNames(), genericParams)
	if err != nil {
		return nil, err
	}
	delegate := &SecretForDecryptImageGeneratorV1{}
	hashParam, found := genericParams["append-hash"]
	if found {
		hashBool, isBool := hashParam.(bool)
		if !isBool {
			return nil, fmt.Errorf("expected bool, found :%v", hashParam)
		}
		delegate.AppendHash = hashBool
		delete(genericParams, "append-hash")
	}
	params := map[string]string{}
	for key, value := range genericParams {
		strVal, isString := value.(string)
		if !isString {
			return nil, fmt.Errorf("expected string, saw %v for '%s'", value, key)
		}
		params[key] = strVal
	}
	delegate.Name = params["name"]
	// delegate.Username = params["docker-username"]
	// delegate.Email = params["docker-email"]
	// delegate.Password = params["docker-password"]
	// delegate.Server = params["docker-server"]
	return delegate.StructuredGenerate()
}

// StructuredGenerate outputs a secret object using the configured fields
func (s SecretForDecryptImageGeneratorV1) StructuredGenerate() (runtime.Object, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	secret := &v1.Secret{}
	secret.Name = s.Name
	secret.Type = v1.SecretTypeDecryptKey
	secret.Data = map[string][]byte{}
	// if len(s.FileSources) > 0 {
	// 	if err := handleFromFileSources(secret, s.FileSources); err != nil {
	// 		return nil, err
	// 	}
	// }
	//if len(s.FileSources) == 0 {
	privateKeyContent, err := handleDecryptCfgJsonContent(s.PrivateKeyPasswds)
	if err != nil {
		return nil, err
	}
	//secret.Data[v1.DockerConfigJsonKey] = dockercfgJsonContent
	secret.Data[v1.ImageDecryptionKey] = privateKeyContent
	//}
	if s.AppendHash {
		h, err := hash.SecretHash(secret)
		if err != nil {
			return nil, err
		}
		secret.Name = fmt.Sprintf("%s-%s", secret.Name, h)
	}
	return secret, nil
}

// ParamNames returns the set of supported input parameters when using the parameter injection generator pattern
func (s SecretForDecryptImageGeneratorV1) ParamNames() []generate.GeneratorParam {
	return []generate.GeneratorParam{
		{Name: "name", Required: true},
		//{Name: "from-file", Required: false},
		{Name: "decrypt-secret", Required: true},
		// {Name: "docker-email", Required: false},
		// {Name: "docker-password", Required: true},
		// {Name: "docker-server", Required: true},
		{Name: "append-hash", Required: false},
	}
}

// validate validates required fields are set to support structured generation
func (s SecretForDecryptImageGeneratorV1) validate() error {
	if len(s.Name) == 0 {
		return fmt.Errorf("name must be specified")
	}

	if len(s.PrivateKeyPasswds) == 0 {
		return fmt.Errorf("private key must be specified")
		// if len(s.Username) == 0 {
		// 	return fmt.Errorf("username must be specified")
		// }
		// if len(s.Password) == 0 {
		// 	return fmt.Errorf("password must be specified")
		// }
		// if len(s.Server) == 0 {
		// 	return fmt.Errorf("server must be specified")
		// }
	}
	return nil
}

// handleDecryptCfgJsonContent serializes a ~/.docker/config.json file
func handleDecryptCfgJsonContent(privateKeyPasswds []string) ([]byte, error) {
	DecryptParams := DecryptConfigEntry{
		PrivateKeyPasswds: privateKeyPasswds,
		//Password:   password,
		// Email:    email,
	}

	// dockerCfgJson := DockerConfigJson{
	// 	Auths: map[string]DockerConfigEntry{server: dockercfgAuth},
	// }

	return json.Marshal(DecryptParams)
}

// DecryptConfigJson represents a local docker auth config file
// for pulling images.
// type DecryptConfigJson struct {
// 	Auths DecryptConfig `json:"auths"`
// 	// +optional
// 	// HttpHeaders map[string]string `json:"HttpHeaders,omitempty"`
// }

// // DecryptConfig represents the config file used by the docker CLI.
// // This config that represents the credentials that should be used
// // when pulling images from specific image repositories.
// type DecryptConfig map[string]DecryptConfigEntry
type DecryptConfigEntry struct {
	PrivateKeyPasswds []string `json:"privatekey"`
	//Password   string `json:"password"`
}
