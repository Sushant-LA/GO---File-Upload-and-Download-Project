package routes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go-file-storage-project/storage"
	"io"
	"net/http"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// type Response struct {
// 	Status  string `json:"status"`
// 	Message string `json:"message"`
// }

// var EncryptionKey = []byte("Sushant@12345678")

func generateKey(pass string, salt []byte) []byte {

	key := pbkdf2.Key([]byte(pass), salt, 1000000, 32, sha256.New)

	return key
}

func generateSalt(size int) []byte {

	salt := make([]byte, size)
	rand.Read(salt)

	return salt
}

func EncryptFile(key, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherText := aesGCM.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

func DecryptFile(key, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	decryptedFile, err := aesGCM.Open(nil, cipherText[:aesGCM.NonceSize()], cipherText[aesGCM.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file: %w", err)
	}

	return decryptedFile, nil
}

func UploadFile(w http.ResponseWriter, r *http.Request) {

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil {
		http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fileType := http.DetectContentType(buffer)
	fmt.Printf("file-type : %s \n", fileType)
	validFileTypes := map[string]bool{
		"text/plain":               true,
		"application/octet-stream": true,
		"image/jpeg":               true,
		"application/pdf":          true,
		"application/vnd.ms-excel": true,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
	}

	if !validFileTypes[fileType] {
		http.Error(w, "Invalid file type: "+fileType, http.StatusBadRequest)
		return
	}

	if _, err := file.Seek(0, 0); err != nil {
		http.Error(w, "Error resetting file pointer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	salt := generateSalt(16)
	os.Setenv("SALT", string(salt))
	fmt.Println("salt: ", salt)
	EncryptionKey := generateKey(os.Getenv("KEY"), salt)

	encryptedData, err := EncryptFile(EncryptionKey, fileData)
	if err != nil {
		http.Error(w, "Error encrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := storage.Uploader(handler.Filename, bytes.NewReader(encryptedData)); err != nil {
		http.Error(w, "File upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "File uploaded successfully!",
	})
}

func DownloadFile(w http.ResponseWriter, r *http.Request) {
	objectName := r.URL.Query().Get("file")
	if objectName == "" {
		http.Error(w, "Missing file query param", http.StatusBadRequest)
		return
	}

	encryptedFile, err := storage.Downloader(objectName)
	if err != nil {
		http.Error(w, "File download failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	EncryptionKey := generateKey(os.Getenv("KEY"), []byte(os.Getenv("SALT")))

	fmt.Println("SALT IN DOWNLOAD FILE: ", []byte(os.Getenv("SALT")))

	decryptedFile, err := DecryptFile(EncryptionKey, encryptedFile)
	if err != nil {
		http.Error(w, "Error decrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fileType := http.DetectContentType(decryptedFile)

	validFileTypes := map[string]bool{
		"text/plain; charset=utf-8": true,
		"application/octet-stream":  true,
		"image/jpeg":                true,
		"application/pdf":           true,
		"application/vnd.ms-excel":  true,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
	}

	if !validFileTypes[fileType] {
		http.Error(w, "Invalid file type: "+fileType, http.StatusForbidden)
		return
	}

	fmt.Printf("File downloaded: %s\n", objectName)

	// if we want the raw file download use the following

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", objectName))
	w.Header().Set("Content-Type", fileType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decryptedFile)))
	_, err = w.Write(decryptedFile)
	if err != nil {
		http.Error(w, "Failed to write file to response: "+err.Error(), http.StatusInternalServerError)
	}

	// if we want to return json response then use the following

	// encodedContent := base64.StdEncoding.EncodeToString(decryptedFile)

	// response := map[string]interface{}{
	// 	"filename":       objectName,
	// 	"file-content":   encodedContent,
	// 	"file-mime-type": fileType,
	// 	"file-length":    len(decryptedFile),
	// }

	// w.Header().Set("Content-Type", "application/json")
	// w.WriteHeader(http.StatusOK)

	// if err := json.NewEncoder(w).Encode(response); err != nil {
	// 	http.Error(w, "Failed to encode JSON response: "+err.Error(), http.StatusInternalServerError)
	// }
}

// func checkNilErr(err error) {

// 	if err != nil {
// 		http.Error(w,"Failed! "+err.Error())
// 		panic(err)
// 	}
// }
