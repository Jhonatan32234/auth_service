package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// SignRequest genera una firma Ed25519 basada en el timestamp, método, ruta y cuerpo de la petición.
func SignRequest(privateKey ed25519.PrivateKey, method, path string, timestamp int64, body []byte) (string, error) {
	data := fmt.Sprintf("%d:%s:%s:%s", timestamp, method, path, string(body))
	sig := ed25519.Sign(privateKey, []byte(data))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyRequest verifica una firma Ed25519 contra los datos provistos.
func VerifyRequest(publicKey ed25519.PublicKey, method, path string, timestamp int64, body []byte, sigStr string) (bool, error) {
	// Prevenir ataques de repetición (límite de 5 minutos)
	now := time.Now().Unix()
	if now-timestamp > 300 || timestamp-now > 300 {
		return false, fmt.Errorf("firma expirada o con marca de tiempo inválida")
	}

	data := fmt.Sprintf("%d:%s:%s:%s", timestamp, method, path, string(body))
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return false, fmt.Errorf("firma no es base64 válido: %w", err)
	}

	return ed25519.Verify(publicKey, []byte(data), sig), nil
}
