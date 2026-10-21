package flowlogs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// azureStore reads a flow log container with the Azure SDK.
type azureStore struct {
	client *container.Client
}

// NewManagedIdentityStore returns a store for container in the storage account at endpoint
// (https://<account>.blob.core.windows.net), signed in as the VM's managed identity. clientID
// selects a user-assigned identity; empty means the system-assigned one. No token is fetched
// until the first request.
func NewManagedIdentityStore(endpoint, containerName, clientID string) (BlobStore, error) {
	opts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
	}
	cred, err := azidentity.NewManagedIdentityCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("managed identity credential: %w", err)
	}
	return NewStore(endpoint, containerName, cred)
}

// NewStore returns a store for container in the storage account at endpoint, using cred.
func NewStore(endpoint, containerName string, cred azcore.TokenCredential) (BlobStore, error) {
	client, err := container.NewClient(containerURL(endpoint, containerName), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("blob container client: %w", err)
	}
	return &azureStore{client: client}, nil
}

func containerURL(endpoint, containerName string) string {
	return strings.TrimRight(endpoint, "/") + "/" + containerName
}

func (s *azureStore) List(ctx context.Context, prefix string) ([]BlobInfo, error) {
	opts := &container.ListBlobsFlatOptions{}
	if prefix != "" {
		opts.Prefix = &prefix
	}
	var out []BlobInfo
	pager := s.client.NewListBlobsFlatPager(opts)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list blobs: %w", err)
		}
		if page.Segment == nil {
			continue
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name == nil || item.Properties == nil || item.Properties.ContentLength == nil ||
				item.Properties.LastModified == nil {
				continue
			}
			out = append(out, BlobInfo{
				Name:         *item.Name,
				Size:         *item.Properties.ContentLength,
				LastModified: *item.Properties.LastModified,
			})
		}
	}
	return out, nil
}

func (s *azureStore) Read(ctx context.Context, name string, offset, count int64) ([]byte, error) {
	resp, err := s.client.NewBlobClient(name).DownloadStream(ctx, &blob.DownloadStreamOptions{
		Range: blob.HTTPRange{Offset: offset, Count: count},
	})
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, count))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

// describeError sorts a poll failure into a kind, so the same failure repeated every poll is
// logged once rather than every minute (an Azure error's text includes a request ID that
// changes each time), and returns a hint for the ones an operator can fix.
func describeError(err error) (kind, hint string) {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		kind = fmt.Sprintf("HTTP %d %s", respErr.StatusCode, respErr.ErrorCode)
		switch respErr.StatusCode {
		case 403:
			hint = "the sensor VM's managed identity needs the Storage Blob Data Reader role on the storage account, " +
				"and a storage account firewall must allow the sensor's network (role assignments can take a few minutes to apply)"
		case 404:
			hint = "check azure_flow_logs.storage_account and azure_flow_logs.container"
		}
		return kind, hint
	}
	first, _, _ := strings.Cut(err.Error(), "\n")
	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) || strings.Contains(err.Error(), "ManagedIdentityCredential") {
		// Keyed by the message, so a different identity error is logged when it replaces one
		return "managed identity: " + first, "the sensor must run on an Azure VM with a managed identity; " +
			"for a user-assigned identity, azure_flow_logs.managed_identity_client_id must be its client ID"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS " + dnsErr.Name, "check azure_flow_logs.storage_account or azure_flow_logs.blob_endpoint, and DNS on the sensor VM"
	}
	// A network error's text names the blob it was reading, so key it by kind instead
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		if errors.Is(err, context.DeadlineExceeded) || netErr.Timeout() {
			return "network timeout", "check the sensor VM's network path to the storage account"
		}
		return "network error", "check the sensor VM's network path to the storage account"
	}
	return first, ""
}

// blobFault reports whether a failed download is about the blob itself, rather than something
// that affects every blob (permissions, throttling, a missing container, the service, the
// network): gone for a blob that no longer exists, aboutBlob for that and any other client
// error about it.
func blobFault(err error) (gone, aboutBlob bool) {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false, false
	}
	switch code := respErr.StatusCode; code {
	case 404:
		// Only BlobNotFound is about this blob; a missing container affects every blob
		gone := respErr.ErrorCode == string(bloberror.BlobNotFound)
		return gone, gone
	case 401, 403, 408, 429:
		return false, false
	default:
		return false, code >= 400 && code < 500
	}
}
