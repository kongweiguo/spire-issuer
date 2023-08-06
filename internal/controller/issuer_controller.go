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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"github.com/kongweiguo/jubilant-controller/internal/authority"
	"github.com/kongweiguo/jubilant-controller/internal/utils"
)

const (
	defaultHealthCheckInterval = time.Minute
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	Logger logr.Logger

	Client                   client.Client
	Kind                     string
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

type issuerContext struct {
	ctx context.Context
	req ctrl.Request

	issuer       client.Object
	issuerSpec   *v1alpha1.IssuerSpec
	issuerStatus *v1alpha1.IssuerStatus
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
	if err := r.Client.Get(ctx, req.NamespacedName, issuer); err != nil {
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

	iCtx := &issuerContext{
		ctx: ctx,
		req: req,

		issuer:       issuer,
		issuerSpec:   issuerSpec,
		issuerStatus: issuerStatus,
	}

	// Always attempt to update the Ready condition
	defer r.updateStatus(iCtx)

	// ready := utils.GetReadyCondition(issuerStatus)
	// if ready == nil {
	// 	r.setStatusAndEvent(&iCtx, v1alpha1.ConditionUnknown, "First seen", nil)
	// 	return ctrl.Result{}, nil
	// }

	result, err = r.reconcileAuthority(iCtx)
	if err != nil {
		utils.SetReadyCondition(issuerStatus, v1alpha1.ConditionFalse, v1alpha1.EventReasonIssuerReconciler, fmt.Sprintf("reconcileAuthority failed, error:%s", err))
		r.recorder.Event(issuer, corev1.EventTypeWarning, v1alpha1.EventReasonIssuerReconciler, err.Error())
		r.Logger.Error(err, "reconcileAuthority failed")
		return ctrl.Result{RequeueAfter: time.Minute * 2}, nil
	}

	utils.SetReadyCondition(issuerStatus, v1alpha1.ConditionTrue, v1alpha1.EventReasonIssuerReconciler, "Success")
	r.recorder.Event(issuer, corev1.EventTypeNormal, v1alpha1.EventReasonIssuerReconciler, "Success")
	r.Logger.Info("Success")

	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

func (r *IssuerReconciler) reconcileAuthority(ictx *issuerContext) (ctrl.Result, error) {

	secret := &corev1.Secret{}
	secretName := types.NamespacedName{Namespace: ictx.req.Namespace, Name: ictx.issuerSpec.SecretName}
	if len(secretName.Namespace) == 0 {
		secretName.Namespace = r.ClusterResourceNamespace
	}

	err := r.Client.Get(ictx.ctx, secretName, secret)
	if err == nil {
		// found
		r.Logger.Info("found secret, trying to check TTL")

		ca, err := authority.SecretToAuthority(secret)
		if err != nil {
			r.Logger.Error(err, "secret to authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		if !r.authorityNeedRotate(ictx, ca) {
			return ctrl.Result{}, nil
		}

		ca, err = r.buildAuthority(ictx)
		if err != nil {
			r.Logger.Error(err, "build authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}
		secret = authority.AuthorityToSecret(&secretName, ca)

		err = r.Client.Update(ictx.ctx, secret)
		if err != nil {
			r.Logger.Error(err, "build authority failed")
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		return ctrl.Result{}, nil
	} else if apierrors.IsNotFound(err) {
		// not found
		r.Logger.Info("not found secret")

		ca, err := r.buildAuthority(ictx)
		if err != nil {
			return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, err
		}

		secret = authority.AuthorityToSecret(&secretName, ca)
		err = r.Client.Create(ictx.ctx, secret)
		if err != nil {
			r.Logger.Error(err, "create secret failed")
			return ctrl.Result{}, fmt.Errorf("create secret failed. not retrying... error: %v", err)
		}

		r.Logger.Info("Create Secret Success")
		return ctrl.Result{}, nil
	} else {
		r.Logger.Error(err, "unexpected Get Secret. not retrying...")
		return ctrl.Result{}, fmt.Errorf("unexpected Get Secret. not retrying... error: %v", err)
	}
}

func (r *IssuerReconciler) buildAuthority(ictx *issuerContext) (*authority.Authority, error) {
	return nil, nil
}

func (r *IssuerReconciler) authorityNeedRotate(ictx *issuerContext, ca *authority.Authority) bool {

	if ca == nil || len(ca.CertChain) < 1 {
		return true
	}

	cert := ca.CertChain[0]
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	now := time.Now()

	// less than 1/3 TTL
	if now.After(notBefore.Add((notAfter.Sub(notBefore)) * 2 / 3)) {
		return true
	}

	return false
}

func (r *IssuerReconciler) updateStatus(ictx *issuerContext) {
	issuerInSystem, err := r.newIssuer()
	if err != nil {
		r.Logger.Error(err, "Unrecognised issuer type")
		return
	}

	if err := r.Client.Get(ictx.ctx, ictx.req.NamespacedName, issuerInSystem); err != nil {
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
