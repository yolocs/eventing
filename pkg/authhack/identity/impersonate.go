package identity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	cloudevents "github.com/cloudevents/sdk-go"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var defaultLifetime int64 = 86400

type ServiceAccountTokens struct {
	cache  *sync.Map
	client kubernetes.Interface
}

func NewServiceAccountTokens(client kubernetes.Interface) *ServiceAccountTokens {
	return &ServiceAccountTokens{
		cache:  &sync.Map{},
		client: client,
	}
}

func (t *ServiceAccountTokens) NewSendingContext(ctx, sendingCTX context.Context, name, target string) (context.Context, error) {
	tk, err := t.GetToken(ctx, name, target)
	if err != nil {
		return nil, err
	}
	return cloudevents.ContextWithHeader(sendingCTX, "Knative-Proxy-Auhtorization", tk), nil
}

func (t *ServiceAccountTokens) GetToken(ctx context.Context, name, audience string) (string, error) {
	val, ok := t.cache.Load(t.cacheKey(name, audience))
	if ok {
		ts := val.(authenticationv1.TokenRequestStatus)
		deadline := metav1.NewTime(time.Now().Add(-5 * time.Minute))
		if !ts.ExpirationTimestamp.Before(&deadline) {
			return ts.Token, nil
		}
	}

	ts, err := t.loadToken(ctx, name, audience)
	if err != nil {
		return "", fmt.Errorf("failed to load token for %s: %w", name, err)
	}

	return ts.Token, nil
}

func (t *ServiceAccountTokens) cacheKey(name, audience string) string {
	return fmt.Sprintf("%s#%s", name, audience)
}

func (t *ServiceAccountTokens) loadToken(ctx context.Context, name, audience string) (*authenticationv1.TokenRequestStatus, error) {
	nameParts := strings.Split(name, ":")
	if len(nameParts) != 4 || nameParts[0] != "system" || nameParts[1] != "serviceaccount" {
		return nil, fmt.Errorf("invalid service account name; expect format 'system:serviceaccount:{namespace}:{serviceaccount}'")
	}
	ns := nameParts[2]
	sa := nameParts[3]

	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &defaultLifetime,
		},
	}

	tresp, err := t.client.CoreV1().ServiceAccounts(ns).CreateToken(sa, treq)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("service account doesn't exist: %w", err)
	} else if err != nil {
		return nil, fmt.Errorf("failed to send TokenRequest: %w", err)
	}

	t.cache.Store(t.cacheKey(name, audience), tresp.Status)
	return &tresp.Status, nil
}
