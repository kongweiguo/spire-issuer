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

package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-logr/logr"
	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"github.com/kongweiguo/jubilant-controller/internal/signer"
	"github.com/kongweiguo/jubilant-controller/internal/utils"
)

const (
	defaultHealthCheckInterval = time.Minute
)

type issuerContext struct {
	ctx context.Context
	req ctrl.Request

	issuer       client.Object
	issuerSpec   *v1alpha1.IssuerSpec
	issuerStatus *v1alpha1.IssuerStatus

	log logr.Logger
}

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	SignerBuilder            signer.SignerBuilder
	recorder                 record.EventRecorder

	Logger logr.Logger
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	r.recorder = mgr.GetEventRecorderFor(v1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}

// +kubebuilder:rbac:groups=jubilant.trustauth.net,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=jubilant.trustauth.net,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := v1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)
	r.Logger = log

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := utils.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	ictx := issuerContext{
		ctx: ctx,
		req: req,

		issuer:       issuer,
		issuerSpec:   issuerSpec,
		issuerStatus: issuerStatus,

		log: log,
	}

	// Always attempt to update the Ready condition
	defer r.applyStatus(&ictx)

	if ready := utils.GetReadyCondition(issuerStatus); ready == nil {
		r.reportStatus(&ictx, v1alpha1.ConditionUnknown, "First seen", nil)
		return ctrl.Result{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rawCertChain, err := r.SignerBuilder(ctx, req.NamespacedName, issuerSpec)
	if err != nil {
		r.reportStatus(&ictx, v1alpha1.ConditionFalse, "SignerBuilder fail", err)
		return ctrl.Result{RequeueAfter: time.Minute * 2}, nil
	}

	rawCertChainPEM := ""
	for _, c := range rawCertChain {
		rawCertChainPEM += fmt.Sprintf("%s\n", utils.X509DERToPEM(c))
	}
	issuerStatus.Certificate = []byte(rawCertChainPEM)

	r.reportStatus(&ictx, v1alpha1.ConditionTrue, "Success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// report gives feedback by updating the Ready Condition of the {Cluster}Issuer
// For added visibility we also log a message and create a Kubernetes Event.
func (r *IssuerReconciler) reportStatus(ictx *issuerContext, conditionStatus v1alpha1.ConditionStatus, message string, err error) {
	eventType := corev1.EventTypeNormal
	if err != nil {
		log.Error(err, message)
		eventType = corev1.EventTypeWarning
		message = fmt.Sprintf("%s: %v", message, err)
	} else {
		log.Info(message)
	}

	r.recorder.Event(
		ictx.issuer,
		eventType,
		v1alpha1.EventReasonIssuerReconciler,
		message,
	)
	utils.SetReadyCondition(ictx.issuerStatus, conditionStatus, v1alpha1.EventReasonIssuerReconciler, message)
}

func (r *IssuerReconciler) applyStatus(ictx *issuerContext) {
	issuerInSystem, err := r.newIssuer()
	if err != nil {
		r.Logger.Error(err, "Unrecognised issuer type")
		return
	}
	if err := r.Get(ictx.ctx, ictx.req.NamespacedName, issuerInSystem); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			r.Logger.Error(err, "unexpected get error")
		}
		r.Logger.Info("Not found. Ignoring.")
		return
	}

	_, issuerStatusInSystem, err := utils.GetSpecAndStatus(issuerInSystem)
	if err != nil {
		r.Logger.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return
	}

	if !utils.DeepEqual(ictx.issuerStatus, issuerStatusInSystem, true) {
		metaAccessor := meta.NewAccessor()
		currentResourceVersion, err := metaAccessor.ResourceVersion(issuerInSystem)
		if err != nil {
			r.Logger.Error(err, "failed to metaAccessor")
			return
		}

		_ = metaAccessor.SetResourceVersion(ictx.issuer, currentResourceVersion)
		err = r.Client.Status().Update(ictx.ctx, ictx.issuer)
		if err != nil {
			r.Logger.Error(err, "failed to update status")
			return
		}

		r.Logger.Info("Update CisCluster status successfully")
	}
}
