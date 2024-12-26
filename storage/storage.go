package storage

import (
	"context"
	"fmt"
	"io"
	"os"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

const bucketName = "my-gcp-storage-bucket-1"

func getClient(ctx context.Context) (*storage.Client, error) {

	credsPath := os.Getenv("GCPPATH")

	fmt.Println(credsPath)

	client, err := storage.NewClient(ctx, option.WithCredentialsFile(credsPath))

	if err != nil {
		return nil, fmt.Errorf("failed to get a client: %w ", err)
	}

	return client, nil

}

func Uploader(objectName string, file io.Reader) error {
	ctx := context.Background()
	client, err := getClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	defer client.Close()

	wc := client.Bucket(bucketName).Object(objectName).NewWriter(ctx)
	defer wc.Close()

	if _, err := io.Copy(wc, file); err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}

func Downloader(objectName string) ([]byte, error) {
	ctx := context.Background()
	client, err := getClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer client.Close()

	rc, err := client.Bucket(bucketName).Object(objectName).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get object reader: %w", err)
	}
	defer rc.Close()

	fileBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return fileBytes, nil
}
