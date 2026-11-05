package receipt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Horizons are the public Horizon servers by network name.
var Horizons = map[string]string{
	"testnet": "https://horizon-testnet.stellar.org",
	"mainnet": "https://horizon.stellar.org",
}

// Horizon looks transactions up through Horizon's REST API.
type Horizon struct {
	URLs map[string]string // network name -> base URL; nil means Horizons
	HTTP *http.Client      // nil means a client with a 20 s timeout
}

// Transaction implements Lookup.
func (h Horizon) Transaction(ctx context.Context, network, hash string) (*Tx, error) {
	urls := h.URLs
	if urls == nil {
		urls = Horizons
	}
	base, ok := urls[network]
	if !ok {
		return nil, fmt.Errorf("unknown network %q", network)
	}
	client := h.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/transactions/"+hash, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("horizon: HTTP %d", resp.StatusCode)
	}
	var t struct {
		Successful bool      `json:"successful"`
		Source     string    `json:"source_account"`
		MemoType   string    `json:"memo_type"`
		Memo       string    `json:"memo"`
		Ledger     uint32    `json:"ledger"`
		CreatedAt  time.Time `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, fmt.Errorf("horizon: %w", err)
	}
	tx := &Tx{Successful: t.Successful, Source: t.Source, Ledger: t.Ledger, ClosedAt: t.CreatedAt}
	if t.MemoType == "hash" {
		b, err := base64.StdEncoding.DecodeString(t.Memo)
		if err == nil && len(b) == 32 {
			tx.MemoHash = new([32]byte)
			copy(tx.MemoHash[:], b)
		}
	}
	return tx, nil
}
