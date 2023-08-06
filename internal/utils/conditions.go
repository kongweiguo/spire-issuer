/*
Copyright 2020 The cert-manager Authors

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

package utils

import (
	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetCondition ...
func SetCondition(status *v1alpha1.IssuerStatus, nc metav1.Condition) {
	var conditions []metav1.Condition
	exist := false

	if nc.LastTransitionTime.IsZero() {
		nc.LastTransitionTime = metav1.Now()
	}
	for _, c := range status.Conditions {
		if c.Type == nc.Type {
			exist = true

			// 只有当"状态"、"信息"、"原因"变更时才需要赋值，更新LastTransitionTime
			if c.Status != nc.Status ||
				c.Message != nc.Message ||
				c.Reason != nc.Reason {
				c = nc
			}
		}
		conditions = append(conditions, c)
	}

	if !exist {
		conditions = append(conditions, nc)
	}

	status.Conditions = conditions
}

func GetCondition(status *v1alpha1.IssuerStatus, conditionType string) (metav1.Condition, bool) {
	for _, v := range status.Conditions {
		if v.Type == conditionType {
			return v, true
		}
	}

	return metav1.Condition{}, false
}
