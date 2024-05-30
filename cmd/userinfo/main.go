package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/chargemasterplc/poc-oidc-alb-test/internal/logging"
	"github.com/chargemasterplc/poc-oidc-alb-test/internal/transports"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sethvargo/go-envconfig"
)

// main is the entry point used by the lambda runtime
func main() {
	handler, err := newHandler(context.Background(), handlerConfig{
		LogOutput: os.Stdout,
		Client:    xray.Client(http.DefaultClient),
		Now:       time.Now,
		EnvLoader: envconfig.OsLookuper(),
	})

	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}

	lambda.Start(handler)
}

// handlerConfig configures how the lambda handler behaves
type handlerConfig struct {
	LogOutput io.Writer          // output destination for the logger
	Client    *http.Client       // http client used for requests
	Now       func() time.Time   // used to lookup the current system time
	EnvLoader envconfig.Lookuper // used to lookup environment variable
}

// handler represents a Lambda function capable of handing a ALB request/response.
type handler func(ctx context.Context, req events.ALBTargetGroupRequest) (*events.ALBTargetGroupResponse, error)

// newHandler creates a lambda function capable of processing JWT tokens
// and returning UserInfo responses.
func newHandler(ctx context.Context, cfg handlerConfig) (handler, error) {
	var env struct {
		Issuer   url.URL    `env:"OIDC_ISSUER,required"`
		LogLevel slog.Level `env:"LOG_LEVEL,default=WARN"`
	}

	// attempt to parse the environment variables
	if err := envconfig.ProcessWith(ctx, &env, cfg.EnvLoader); err != nil {
		return nil, fmt.Errorf("parsing environment variables: %w", err)
	}

	log := logging.New(
		logging.JSON,
		logging.WithOutput(cfg.LogOutput),
		logging.WithLevel(env.LogLevel),

		// the below extracts the Lambda request ID from each request and adds
		// it to each log message
		logging.WithContextResolver(func(ctx context.Context) []slog.Attr {
			if lambdaCtx, ok := lambdacontext.FromContext(ctx); ok {
				return []slog.Attr{slog.String("requestId", lambdaCtx.AwsRequestID)}
			}
			return nil
		}),
	)

	// create a http client with our middleware applied
	client := addHTTPClientTransports(cfg.Client, log)

	// the provider is loaded by calling the OIDC .well-known endpoint, which
	// exposes OIDC settings such as supported algorithms and scopes by the issuer.
	provider, err := oidc.NewProvider(
		oidc.ClientContext(ctx, client),
		env.Issuer.String(),
	)

	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}

	// using the loaded provider we can create a verifier, which is used to ensure
	// that any tokens supplied were issued by issuer.
	verifier := provider.Verifier(&oidc.Config{
		// we're mainly verifying the token as good practice rather
		// than ensuring it's entirely secure. If we start returning
		// more data than the the user's SUB, this needs to be reviewed.
		SkipClientIDCheck: true,
		Now:               cfg.Now,
	})

	// all the decadencies are now loaded, return the actual lambda
	// function handler
	return func(ctx context.Context, req events.ALBTargetGroupRequest) (*events.ALBTargetGroupResponse, error) {
		ctx = oidc.ClientContext(ctx, client)

		log.DebugContext(ctx, "received alb request",
			slog.String("method", req.HTTPMethod),
			slog.String("path", req.Path),
			slog.Int("bodyLength", len(req.Body)),
			slog.String("targetGroupArn", req.RequestContext.ELB.TargetGroupArn),
		)

		token, err := verifyToken(ctx, verifier, req.Headers)
		if err != nil {
			log.WarnContext(ctx, "invalid authorization token",
				slog.Any("err", err),
			)

			return &events.ALBTargetGroupResponse{StatusCode: http.StatusForbidden}, nil
		}

		log.DebugContext(ctx, "verified token, creating userinfo",
			slog.String("token_issuer", token.Issuer),
			slog.Any("token_audience", token.Audience),
			slog.Time("token_issued_at", token.IssuedAt),
			slog.Time("token_expiry", token.Expiry),
		)

		// build up the userinfo result
		var sb strings.Builder

		if err := json.NewEncoder(&sb).Encode(struct {
			Subject string `json:"sub"`
		}{
			Subject: token.Subject,
		}); err != nil {
			return nil, fmt.Errorf("encoding userinfo: %w", err)
		}

		log.DebugContext(ctx, "authenticated token, returning user profile",
			slog.Int("tokenSize", sb.Len()),
		)

		return &events.ALBTargetGroupResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       sb.String()[:sb.Len()-1], // remove the trailing \n from the JSON
		}, nil
	}, nil
}

// verifyToken extracts the authorization header from the request
// and validates the supplied token against the verifier. If the token
// is invalid, or not supplied an error is returned.
func verifyToken(
	ctx context.Context,
	verifier *oidc.IDTokenVerifier,
	headers map[string]string,
) (*oidc.IDToken, error) {
	// lookup the header from the supplied list
	auth, ok := headers["authorization"]

	if !ok {
		return nil, errors.New("authorization header not supplied")
	}

	// tidy up the token
	auth = strings.TrimSpace(auth)
	auth = strings.TrimPrefix(auth, "Bearer ")

	if auth == "" {
		return nil, fmt.Errorf("authorization header empty")
	}

	// parse and verify the token
	token, err := verifier.Verify(ctx, auth)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return token, nil
}

// addHTTPClientTransports creates a new http client with additional
// transports added.
func addHTTPClientTransports(client *http.Client, log *slog.Logger) *http.Client {
	clone := *client

	if clone.Transport == nil {
		clone.Transport = http.DefaultTransport
	}

	clone.Transport = &transports.LoggingRoundTripper{
		Log:  log,
		Next: clone.Transport,
	}

	return &clone
}
