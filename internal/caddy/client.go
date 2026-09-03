package caddy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const maxErrorBody = 64 << 10

type Loader interface {
	Load(context.Context, []byte) error
}

type Client struct {
	httpClient *http.Client
	endpoint   string
}

func NewUnixClient(socketPath string, timeout time.Duration) (*Client, error) {
	if socketPath == "" || socketPath[0] != '/' {
		return nil, errors.New("Caddy administration socket must be absolute")
	}
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: transport, Timeout: timeout},
		endpoint:   "http://caddy/load",
	}, nil
}

func NewHTTPClient(endpoint string, timeout time.Duration) *Client {
	return &Client{httpClient: &http.Client{Timeout: timeout}, endpoint: endpoint}
}

func (client *Client) Load(ctx context.Context, document []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("create Caddy load request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("load Caddy configuration: %w", err)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBody+1))
	if readErr != nil {
		return fmt.Errorf("read Caddy response: %w", readErr)
	}
	if len(body) > maxErrorBody {
		return errors.New("Caddy response exceeded size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Caddy rejected configuration with %s: %s", response.Status, string(bytes.TrimSpace(body)))
	}
	return nil
}
