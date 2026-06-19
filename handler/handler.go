package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"image-safety-detector/detector"
)

type DetectRequest struct {
	ImagePath string `json:"image_path"`
}

type APIResponse struct {
	Success bool                     `json:"success"`
	Data    *detector.DetectionResult `json:"data,omitempty"`
	Error   string                   `json:"error,omitempty"`
}

type PoolStatsResponse struct {
	Success      bool   `json:"success"`
	WorkerCount  int    `json:"worker_count"`
	QueueSize    int    `json:"queue_size"`
	PendingTasks int    `json:"pending_tasks"`
	Processed    uint64 `json:"processed_total"`
	Error        string `json:"error,omitempty"`
}

type Handler struct {
	Pool            *detector.Pool
	DefaultTimeout  time.Duration
}

func NewHandler(pool *detector.Pool) *Handler {
	return &Handler{
		Pool:           pool,
		DefaultTimeout: 10 * time.Second,
	}
}

func (h *Handler) HandleDetect(w http.ResponseWriter, r *http.Request) {
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

	h.submitAndRespond(w, r, absPath)
}

func (h *Handler) HandleDetectForm(w http.ResponseWriter, r *http.Request) {
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

	h.submitAndRespond(w, r, absPath)
}

func (h *Handler) submitAndRespond(w http.ResponseWriter, r *http.Request, absPath string) {
	ctx := r.Context()
	timeoutCtx, cancel := contextWithTimeout(ctx, h.DefaultTimeout)
	defer cancel()

	result, err := h.Pool.Submit(timeoutCtx, absPath)
	if err != nil {
		statusCode := http.StatusOK
		switch {
		case errors.Is(err, detector.ErrPoolClosed):
			statusCode = http.StatusServiceUnavailable
		case errors.Is(err, detector.ErrPoolBusy):
			statusCode = http.StatusTooManyRequests
		default:
			statusCode = http.StatusRequestTimeout
		}
		writeJSON(w, statusCode, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("detection submission failed: %v", err),
		})
		return
	}

	statusCode := http.StatusOK
	success := result.Error == ""

	writeJSON(w, statusCode, APIResponse{
		Success: success,
		Data:    &result,
	})
}

func (h *Handler) HandlePoolStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	workerCount, queueSize, pendingTasks, processed := h.Pool.Stats()
	writeJSON(w, http.StatusOK, PoolStatsResponse{
		Success:      true,
		WorkerCount:  workerCount,
		QueueSize:    queueSize,
		PendingTasks: pendingTasks,
		Processed:    processed,
	})
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	workerCount, _, pendingTasks, processed := h.Pool.Stats()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "ok",
		"pool_workers":   workerCount,
		"pending_tasks":  pendingTasks,
		"processed":      processed,
	})
}

func contextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := parent.Deadline()
	if ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < timeout {
			return context.WithTimeout(parent, remaining)
		}
	}
	return context.WithTimeout(parent, timeout)
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
