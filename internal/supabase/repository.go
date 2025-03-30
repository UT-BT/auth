package supabase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Repository defines the interface for Supabase database operations
type Repository interface {
	UpsertRegisteredHWID(input *RegisteredHWIDInput) (*RegisteredHWID, error)
	GetRegisteredHWID(userID string) (*RegisteredHWID, error)
}

// repository implements the Repository interface
type repository struct {
	baseURL    string
	serviceKey string
	client     *http.Client
}

// NewRepository creates a new Supabase repository instance
func NewRepository(baseURL, serviceKey string) Repository {
	return &repository{
		baseURL:    baseURL,
		serviceKey: serviceKey,
		client:     &http.Client{},
	}
}

func (r *repository) UpsertRegisteredHWID(input *RegisteredHWIDInput) (*RegisteredHWID, error) {
	endpoint := fmt.Sprintf("%s/rest/v1/registered_hwids", r.baseURL)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("apikey", r.serviceKey)
	req.Header.Set("Authorization", "Bearer "+r.serviceKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "resolution=merge-duplicates,return=representation")
	req.Header.Set("Accept-Profile", "auth")
	req.Header.Set("Content-Profile", "auth")
	q := req.URL.Query()
	q.Add("on_conflict", "user_id")
	req.URL.RawQuery = q.Encode()

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	respBody, _ := io.ReadAll(resp.Body)
	log.Debug().Msgf("Response body: %s", string(respBody))

	var results []RegisteredHWID
	if err := json.Unmarshal(respBody, &results); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no result returned from upsert operation")
	}

	return &results[0], nil
}

func (r *repository) GetRegisteredHWID(userID string) (*RegisteredHWID, error) {
	endpoint := fmt.Sprintf("%s/rest/v1/registered_hwids", r.baseURL)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("apikey", r.serviceKey)
	req.Header.Set("Authorization", "Bearer "+r.serviceKey)
	req.Header.Set("Accept", "application/vnd.pgrst.object+json")
	req.Header.Set("Accept-Profile", "auth")
	req.Header.Set("Content-Profile", "auth")

	q := req.URL.Query()
	q.Add("select", "*")
	q.Add("user_id", fmt.Sprintf("eq.%s", userID))
	q.Add("limit", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	var result RegisteredHWID
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
