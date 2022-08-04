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

package tableconvertor

import (
	"context"
	"fmt"

	"github.com/onmetal/kolm/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/meta/table"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	objectMetaSwaggerDoc = metav1.ObjectMeta{}.SwaggerDoc()

	headers = []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Description: objectMetaSwaggerDoc["name"]},
		{Name: "ETCD", Type: "string", Description: "Address of the etcd."},
		{Name: "APIServer", Type: "string", Description: "Address of the api server."},
	}
)

type apiTableConvertor struct{}

func (apiTableConvertor) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	tab := &metav1.Table{
		ColumnDefinitions: headers,
	}

	if m, err := meta.ListAccessor(obj); err != nil {
		tab.ResourceVersion = m.GetResourceVersion()
		tab.Continue = m.GetContinue()
	} else if m, err := meta.CommonAccessor(obj); err != nil {
		tab.ResourceVersion = m.GetResourceVersion()
	}

	var err error
	tab.Rows, err = table.MetaToTableRow(obj, func(obj runtime.Object, m metav1.Object, name, age string) (cells []interface{}, err error) {
		api := obj.(*v1alpha1.API)

		cells = append(cells, name)
		cells = append(cells, fmt.Sprintf("http://%s:%d", api.ETCD.Host, api.ETCD.Port))
		cells = append(cells, fmt.Sprintf("https://%s:%d", api.APIServer.Host, api.APIServer.Port))
		return cells, nil
	})
	return tab, err
}

func ConvertAPIToTable(obj runtime.Object) (*metav1.Table, error) {
	return apiTableConvertor{}.ConvertToTable(context.Background(), obj, &metav1.TableOptions{})
}
