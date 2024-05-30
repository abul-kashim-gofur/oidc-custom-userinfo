package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/chargemasterplc/poc-oidc-alb-test/internal/test"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/sethvargo/go-envconfig"
	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	t.Parallel()

	oidcServer := test.OIDCServer(t)
	oidcURL := oidcServer.URL()
	maliciousOIDC := test.OIDCServer(t)
	validEnv := map[string]string{
		"OIDC_ISSUER": oidcURL.String(),
		"LOG_LEVEL":   "debug",
	}

	tt := []struct {
		name string

		givenEnv        map[string]string
		givenALBRequest events.ALBTargetGroupRequest

		wantCreateErr   string
		wantALBResponse *events.ALBTargetGroupResponse
	}{
		{
			name:          "given env without OIDC_ISSUER, return err",
			wantCreateErr: "parsing environment variables: Issuer: missing required value: OIDC_ISSUER",
		},
		{
			name:          "given unreachable issuer, return err",
			givenEnv:      map[string]string{"OIDC_ISSUER": "https://unknown.localhost"},
			wantCreateErr: `provider: Get "https://unknown.localhost/.well-known/openid-configuration": dial tcp 127.0.0.1:443: connect: connection refused`,
		},
		{
			name:            "given request without a auth header, return 403",
			givenEnv:        validEnv,
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},
		{
			name:            "given request without a valid auth token, return 403",
			givenEnv:        validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{Headers: map[string]string{"authorization": "invalid"}},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},
		{
			name:            "given request with a empty auth header, return 403",
			givenEnv:        validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{Headers: map[string]string{"authorization": "      "}},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},
		{
			name:            "given request without a valid auth token, return 403",
			givenEnv:        validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{Headers: map[string]string{"authorization": "invalid"}},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},

		// =====================
		// Invalid JWT Tests
		// =====================
		{
			name:     "given request with JWT issued by another issuer, return 403",
			givenEnv: validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{
				Headers: map[string]string{
					"authorization": oidcServer.GenerateJWT(t, jwt.Claims{Issuer: "another-issuer"}),
				},
			},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},
		{
			name:     "given request with expired JWT, return 403",
			givenEnv: validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{
				Headers: map[string]string{
					"authorization": oidcServer.GenerateJWT(t, jwt.Claims{Expiry: jwt.NewNumericDate(test.Now().Add(-time.Second))}),
				},
			},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},
		{
			name:     "given request with JWT signed by another server, return 403",
			givenEnv: validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{
				Headers: map[string]string{
					"authorization": maliciousOIDC.GenerateJWT(t, jwt.Claims{Issuer: oidcServer.Issuer()}),
				},
			},
			wantALBResponse: &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden},
		},

		// =====================
		// Valid Token tests
		// =====================
		{
			name:     "given token created by issuer, return user details",
			givenEnv: validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{
				Headers: map[string]string{
					"authorization": oidcServer.GenerateJWT(t, jwt.Claims{}),
				},
			},
			wantALBResponse: &events.ALBTargetGroupResponse{
				StatusCode: http.StatusOK,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"sub":"user_sub"}`,
			},
		},
		{
			name:     "given a valid token with different aud, return user details",
			givenEnv: validEnv,
			givenALBRequest: events.ALBTargetGroupRequest{
				Headers: map[string]string{
					"authorization": oidcServer.GenerateJWT(t, jwt.Claims{
						Audience: []string{"first", "second"},
					}),
				},
			},
			wantALBResponse: &events.ALBTargetGroupResponse{
				StatusCode: http.StatusOK,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"sub":"user_sub"}`,
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := require.New(t)
			ctx := lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{AwsRequestID: tc.name})
			h, err := newHandler(ctx, handlerConfig{
				LogOutput: test.TBWriter(t),
				Client:    http.DefaultClient,
				Now:       test.Now,
				EnvLoader: envconfig.MapLookuper(tc.givenEnv),
			})

			if tc.wantCreateErr != "" {
				r.EqualError(err, tc.wantCreateErr)
				r.Nil(h)
				return
			}

			r.NoError(err)
			r.NotNil(h)

			res, err := h(ctx, tc.givenALBRequest)

			r.NoError(err)
			r.Equal(tc.wantALBResponse, res)
		})
	}
}

func BenchmarkValidTokenProcessing(b *testing.B) {
	r := require.New(b)
	ctx := context.Background()
	oidcServer := test.OIDCServer(b)
	oidcURL := oidcServer.URL()
	req := events.ALBTargetGroupRequest{
		Headers: map[string]string{
			"authorization": oidcServer.GenerateJWT(b, jwt.Claims{}),
		},
	}

	h, err := newHandler(ctx, handlerConfig{
		LogOutput: test.TBWriter(b),
		Client:    http.DefaultClient,
		Now:       test.Now,
		EnvLoader: envconfig.MapLookuper(map[string]string{
			"OIDC_ISSUER": oidcURL.String(),
			"LOG_LEVEL":   "warn",
		}),
	})

	r.NoError(err)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := h(ctx, req)
		r.NoError(err)
	}
}
