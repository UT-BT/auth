package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/UT-BT/auth/internal/auth/models"
	"github.com/rs/zerolog/log"
)

// HWIDRepository defines the interface for handling hardware ID operations
type HWIDRepository interface {
	UpsertRegisteredHWID(input *models.RegisteredHWIDInput) (*models.RegisteredHWID, error)
	GetRegisteredHWID(userID string) (*models.RegisteredHWID, error)
}

type hwidRepository struct {
	baseURL    string
	serviceKey string
	client     *http.Client
}

// NewHWIDRepository creates a new HWID repository instance
func NewHWIDRepository(baseURL, serviceKey string) HWIDRepository {
	return &hwidRepository{
		baseURL:    baseURL,
		serviceKey: serviceKey,
		client:     &http.Client{},
	}
}

func (r *hwidRepository) UpsertRegisteredHWID(input *models.RegisteredHWIDInput) (*models.RegisteredHWID, error) {
	endpoint := fmt.Sprintf("%s/rest/v1/registered_hwids", r.baseURL)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

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

	var results []models.RegisteredHWID
	if err := json.Unmarshal(respBody, &results); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no result returned from upsert operation")
	}

	return &results[0], nil
}

func (r *hwidRepository) GetRegisteredHWID(userID string) (*models.RegisteredHWID, error) {
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

	var result models.RegisteredHWID
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
