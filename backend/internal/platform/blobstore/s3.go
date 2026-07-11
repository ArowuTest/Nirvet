package blobstore

// S3-compatible object store adapter (ADR-0005). Works with Backblaze B2, Cloudflare R2, AWS S3, MinIO, and
// GCS's S3-interoperability endpoint — one adapter for the interim durable store AND production. Config comes
// entirely from the environment; the secret key is NEVER held anywhere but the process env + the S3 client.
//
//   NIRVET_S3_ENDPOINT   host only, e.g. s3.us-east-005.backblazeb2.com   (required to select S3)
//   NIRVET_S3_BUCKET     bucket name                                       (required)
//   NIRVET_S3_KEY_ID     access key id                                     (required)
//   NIRVET_S3_APP_KEY    secret access key                                 (required)
//   NIRVET_S3_REGION     region, e.g. us-east-005 (default derived / us-east-1)
//   NIRVET_S3_INSECURE   "true" to use http (dev/MinIO only; default https)

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type s3Config struct {
	endpoint, bucket, keyID, appKey, region string
	insecure                                bool
}

// s3ConfigFromEnv returns the S3 config and whether S3 is selected (all required vars present).
func s3ConfigFromEnv() (s3Config, bool) {
	c := s3Config{
		endpoint: os.Getenv("NIRVET_S3_ENDPOINT"),
		bucket:   os.Getenv("NIRVET_S3_BUCKET"),
		keyID:    os.Getenv("NIRVET_S3_KEY_ID"),
		appKey:   os.Getenv("NIRVET_S3_APP_KEY"),
		region:   os.Getenv("NIRVET_S3_REGION"),
		insecure: os.Getenv("NIRVET_S3_INSECURE") == "true",
	}
	if c.region == "" {
		c.region = "us-east-1"
	}
	ok := c.endpoint != "" && c.bucket != "" && c.keyID != "" && c.appKey != ""
	return c, ok
}

type s3Store struct {
	client *minio.Client
	bucket string
}

// newS3 builds the S3-compatible store. Path-style addressing (BucketLookupPath) avoids virtual-host/TLS/DNS
// problems with non-DNS-compliant or mixed-case bucket names (e.g. a B2 bucket named "Nirvet").
func newS3(c s3Config) (Store, error) {
	client, err := minio.New(c.endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(c.keyID, c.appKey, ""),
		Secure:       !c.insecure,
		Region:       c.region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("blobstore: s3 client: %w", err)
	}
	return &s3Store{client: client, bucket: c.bucket}, nil
}

func (s *s3Store) Backend() string { return "s3" }

func (s *s3Store) Put(ctx context.Context, tenantID uuid.UUID, key string, data []byte) (string, error) {
	obj := objectKey(tenantID, key)
	_, err := s.client.PutObject(ctx, s.bucket, obj, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("blobstore: s3 put: %w", err)
	}
	return "s3://" + obj, nil
}

func (s *s3Store) Get(ctx context.Context, uri string) ([]byte, error) {
	obj, err := s.objectFromURI(uri)
	if err != nil {
		return nil, err
	}
	r, err := s.client.GetObject(ctx, s.bucket, obj, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (s *s3Store) Delete(ctx context.Context, uri string) error {
	obj, err := s.objectFromURI(uri)
	if err != nil {
		return err
	}
	return s.client.RemoveObject(ctx, s.bucket, obj, minio.RemoveObjectOptions{})
}

// objectFromURI maps a stored s3:// URI back to its object key, rejecting a non-s3 scheme (defence in depth,
// like the local store's resolve()).
func (s *s3Store) objectFromURI(uri string) (string, error) {
	if !strings.HasPrefix(uri, "s3://") {
		return "", fmt.Errorf("blobstore: unsupported blob URI scheme")
	}
	return strings.TrimPrefix(uri, "s3://"), nil
}

// objectKey builds a tenant-scoped, traversal-safe object key: tenant/<uuid>/<cleaned key>. Cleaning the key
// against a leading slash defeats any embedded "../" before it can escape the tenant prefix.
func objectKey(tenantID uuid.UUID, key string) string {
	clean := strings.TrimPrefix(path.Clean("/"+key), "/")
	return path.Join("tenant", tenantID.String(), clean)
}
