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
	"testing"

	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestSetReadyCondition(t *testing.T) {
	var issuerStatus v1alpha1.IssuerStatus

	SetReadyCondition(&issuerStatus, v1alpha1.ConditionTrue, "reason1", "message1")
	assert.Equal(t, "message1", GetReadyCondition(&issuerStatus).Message)

	SetReadyCondition(&issuerStatus, v1alpha1.ConditionFalse, "reason2", "message2")
	assert.Equal(t, "message2", GetReadyCondition(&issuerStatus).Message)
}
