package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"image-safety-detector/detector"
)

type DetectRequest struct {
	ImagePath string `json:"image_path"`
}

type APIResponse struct {
	Success bool                `json:"success"`
	Data    *detector.DetectionResult `json:"data,omitempty"`
	Error   string              `json:"error,omitempty"`
}

func HandleDetect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Error:   "only POST method is allowed",
		})
		return
	}

	var req DetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	imagePath := strings.TrimSpace(req.ImagePath)
	if imagePath == "" {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "image_path is required",
		})
		return
	}

	absPath, err := filepath.Abs(imagePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid file path: %v", err),
		})
		return
	}

	result := detector.Detect(absPath)

	statusCode := http.StatusOK
	if !result.IsSafe && result.Error == "" {
		statusCode = http.StatusOK
	} else if result.Error != "" && !result.IsSafe {
		statusCode = http.StatusOK
	}

	writeJSON(w, statusCode, APIResponse{
		Success: result.Error == "",
		Data:    &result,
	})
}

func HandleDetectForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Error:   "only POST method is allowed",
		})
		return
	}

	imagePath := r.FormValue("image_path")
	if imagePath == "" {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "image_path is required",
		})
		return
	}

	absPath, err := filepath.Abs(imagePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid file path: %v", err),
		})
		return
	}

	result := detector.Detect(absPath)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: result.Error == "",
		Data:    &result,
	})
}

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
