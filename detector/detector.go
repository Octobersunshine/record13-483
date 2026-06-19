package detector

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"strings"
)

type SafetyLevel string

const (
	Safe         SafetyLevel = "safe"
	Suspicious   SafetyLevel = "suspicious"
	Unsafe       SafetyLevel = "unsafe"
)

type DetectionCategory string

const (
	CategoryNone          DetectionCategory = "none"
	CategorySkinExposure  DetectionCategory = "skin_exposure"
	CategoryCorrupted     DetectionCategory = "corrupted"
	CategoryInvalidFormat DetectionCategory = "invalid_format"
)

type DetectionResult struct {
	IsSafe       bool              `json:"is_safe"`
	SafetyLevel SafetyLevel       `json:"safety_level"`
	Score        float64           `json:"score"`
	Categories   []DetectionDetail `json:"categories,omitempty"`
	FilePath     string            `json:"file_path"`
	FileName     string            `json:"file_name"`
	ImageSize    string            `json:"image_size,omitempty"`
	Error        string            `json:"error,omitempty"`
	ProcessedBy  int               `json:"-"`
}

type DetectionDetail struct {
	Category    DetectionCategory `json:"category"`
	Confidence  float64           `json:"confidence"`
	Description string            `json:"description"`
}

type Task struct {
	ImagePath string
	ResultCh  chan DetectionResult
	Ctx       context.Context
}

type Pool struct {
	workerCount int
	queueSize   int
	taskCh      chan Task
	wg          sync.WaitGroup
	shutdownCh  chan struct{}
	once        sync.Once
	closed      atomic.Bool
	processed   atomic.Uint64
}

type PoolOption func(*Pool)

const (
	MaxBatchSize = 50
)

var (
	ErrPoolClosed   = errors.New("detector pool is closed")
	ErrPoolBusy     = errors.New("detector pool is busy, please retry later")
	ErrTaskCanceled = errors.New("task canceled before processing")
	ErrBatchEmpty   = errors.New("batch request contains no valid image paths")
	ErrBatchTooLarge = errors.New(fmt.Sprintf("batch size exceeds maximum limit of %d", MaxBatchSize))

	allowedExtensions = map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".bmp":  true,
		".gif":  true,
		".webp": true,
	}
)

func WithWorkerCount(n int) PoolOption {
	return func(p *Pool) {
		if n > 0 {
			p.workerCount = n
		}
	}
}

func WithQueueSize(n int) PoolOption {
	return func(p *Pool) {
		if n > 0 {
			p.queueSize = n
		}
	}
}

func NewPool(opts ...PoolOption) *Pool {
	p := &Pool{
		workerCount: runtime.NumCPU(),
		queueSize:   128,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.workerCount < 1 {
		p.workerCount = 1
	}
	if p.queueSize < 1 {
		p.queueSize = 1
	}

	p.taskCh = make(chan Task, p.queueSize)
	p.shutdownCh = make(chan struct{})

	p.wg.Add(p.workerCount)
	for i := 0; i < p.workerCount; i++ {
		go p.worker(i)
	}
	return p
}

func (p *Pool) worker(id int) {
	defer p.wg.Done()

	localBuf := make([]DetectionDetail, 0, 4)

	for {
		select {
		case task, ok := <-p.taskCh:
			if !ok {
				return
			}
			result := p.processTask(task, id, &localBuf)
			select {
			case task.ResultCh <- result:
			case <-task.Ctx.Done():
			case <-p.shutdownCh:
				select {
				case task.ResultCh <- result:
				default:
				}
			}
		case <-p.shutdownCh:
			return
		}
	}
}

func (p *Pool) processTask(task Task, workerID int, localBuf *[]DetectionDetail) DetectionResult {
	p.processed.Add(1)

	select {
	case <-task.Ctx.Done():
		return DetectionResult{
			FilePath:    task.ImagePath,
			FileName:    filepath.Base(task.ImagePath),
			Error:       ErrTaskCanceled.Error(),
			ProcessedBy: workerID,
		}
	default:
	}

	result := doDetect(task.ImagePath, localBuf)
	result.ProcessedBy = workerID
	return result
}

func (p *Pool) Submit(ctx context.Context, imagePath string) (DetectionResult, error) {
	if p.closed.Load() {
		return DetectionResult{}, ErrPoolClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resultCh := make(chan DetectionResult, 1)
	task := Task{
		ImagePath: imagePath,
		ResultCh:  resultCh,
		Ctx:       ctx,
	}

	select {
	case p.taskCh <- task:
	case <-ctx.Done():
		return DetectionResult{}, ctx.Err()
	case <-p.shutdownCh:
		return DetectionResult{}, ErrPoolClosed
	default:
		return DetectionResult{}, ErrPoolBusy
	}

	select {
	case result := <-resultCh:
		return result, nil
	case <-ctx.Done():
		return DetectionResult{}, ctx.Err()
	case <-p.shutdownCh:
		select {
		case result := <-resultCh:
			return result, nil
		default:
			return DetectionResult{}, ErrPoolClosed
		}
	}
}

func (p *Pool) SubmitWithTimeout(imagePath string, timeout time.Duration) (DetectionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.Submit(ctx, imagePath)
}

func (p *Pool) Shutdown(timeout ...time.Duration) error {
	var err error
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.shutdownCh)
		close(p.taskCh)

		if len(timeout) > 0 && timeout[0] > 0 {
			done := make(chan struct{})
			go func() {
				p.wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(timeout[0]):
				err = errors.New("pool shutdown timed out, some workers may not have finished")
			}
		} else {
			p.wg.Wait()
		}
	})
	return err
}

func (p *Pool) Stats() (workerCount, queueSize, pendingTasks int, processed uint64) {
	workerCount = p.workerCount
	queueSize = p.queueSize
	pendingTasks = len(p.taskCh)
	processed = p.processed.Load()
	return
}

type BatchResult struct {
	Total      int               `json:"total"`
	SafeCount  int               `json:"safe_count"`
	Suspicious int               `json:"suspicious_count"`
	UnsafeCount int              `json:"unsafe_count"`
	Results    []DetectionResult `json:"results"`
}

func (p *Pool) SubmitBatch(ctx context.Context, imagePaths []string) (BatchResult, error) {
	if p.closed.Load() {
		return BatchResult{}, ErrPoolClosed
	}
	if len(imagePaths) == 0 {
		return BatchResult{}, ErrBatchEmpty
	}
	if len(imagePaths) > MaxBatchSize {
		return BatchResult{}, ErrBatchTooLarge
	}
	if ctx == nil {
		ctx = context.Background()
	}

	type indexedResult struct {
		index  int
		result DetectionResult
		err    error
	}

	resultCh := make(chan indexedResult, len(imagePaths))
	pending := 0

	for i, path := range imagePaths {
		path := path
		idx := i

		taskResultCh := make(chan DetectionResult, 1)
		task := Task{
			ImagePath: path,
			ResultCh:  taskResultCh,
			Ctx:       ctx,
		}

		submitted := false
		select {
		case p.taskCh <- task:
			submitted = true
			pending++
		case <-ctx.Done():
			resultCh <- indexedResult{index: idx, err: ctx.Err()}
		case <-p.shutdownCh:
			resultCh <- indexedResult{index: idx, err: ErrPoolClosed}
		default:
			resultCh <- indexedResult{index: idx, err: ErrPoolBusy}
		}

		if submitted {
			go func() {
				select {
				case result := <-taskResultCh:
					resultCh <- indexedResult{index: idx, result: result}
				case <-ctx.Done():
					resultCh <- indexedResult{index: idx, err: ctx.Err()}
				case <-p.shutdownCh:
					select {
					case result := <-taskResultCh:
						resultCh <- indexedResult{index: idx, result: result}
					default:
						resultCh <- indexedResult{index: idx, err: ErrPoolClosed}
					}
				}
			}()
		}
	}

	batch := BatchResult{
		Total:   len(imagePaths),
		Results: make([]DetectionResult, len(imagePaths)),
	}

	for i := 0; i < len(imagePaths); i++ {
		select {
		case ir := <-resultCh:
			if ir.err != nil {
				batch.Results[ir.index] = DetectionResult{
					FilePath: imagePaths[ir.index],
					FileName: filepath.Base(imagePaths[ir.index]),
					IsSafe:   false,
					SafetyLevel: Unsafe,
					Error:    ir.err.Error(),
				}
				batch.UnsafeCount++
			} else {
				batch.Results[ir.index] = ir.result
				switch ir.result.SafetyLevel {
				case Safe:
					batch.SafeCount++
				case Suspicious:
					batch.Suspicious++
				case Unsafe:
					batch.UnsafeCount++
				}
			}
		case <-ctx.Done():
			for j := i; j < len(imagePaths); j++ {
				if batch.Results[j].FilePath == "" {
					batch.Results[j] = DetectionResult{
						FilePath: imagePaths[j],
						FileName: filepath.Base(imagePaths[j]),
						IsSafe:   false,
						SafetyLevel: Unsafe,
						Error:    "batch canceled",
					}
					batch.UnsafeCount++
				}
			}
			return batch, ctx.Err()
		}
	}

	return batch, nil
}

func Detect(imagePath string) DetectionResult {
	localBuf := make([]DetectionDetail, 0, 4)
	return doDetect(imagePath, &localBuf)
}

func doDetect(imagePath string, detailBuf *[]DetectionDetail) DetectionResult {
	result := DetectionResult{
		FilePath: imagePath,
		FileName: filepath.Base(imagePath),
	}

	ext := strings.ToLower(filepath.Ext(imagePath))
	if !allowedExtensions[ext] {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
		result.Score = 0
		result.Error = fmt.Sprintf("unsupported image format: %s", ext)
		*detailBuf = (*detailBuf)[:0]
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategoryInvalidFormat,
			Confidence:  1.0,
			Description: fmt.Sprintf("file extension '%s' is not a supported image format", ext),
		})
		result.Categories = append([]DetectionDetail(nil), *detailBuf...)
		return result
	}

	info, err := os.Stat(imagePath)
	if err != nil {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
		result.Score = 0
		if os.IsNotExist(err) {
			result.Error = "file does not exist"
		} else {
			result.Error = fmt.Sprintf("cannot access file: %v", err)
		}
		return result
	}

	if info.Size() == 0 {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
		result.Score = 0
		result.Error = "file is empty"
		*detailBuf = (*detailBuf)[:0]
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategoryCorrupted,
			Confidence:  1.0,
			Description: "image file is empty (0 bytes)",
		})
		result.Categories = append([]DetectionDetail(nil), *detailBuf...)
		return result
	}

	file, err := os.Open(imagePath)
	if err != nil {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
		result.Score = 0
		result.Error = fmt.Sprintf("cannot open file: %v", err)
		return result
	}
	defer file.Close()

	img, format, err := image.Decode(file)
	if err != nil {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
		result.Score = 0
		result.Error = fmt.Sprintf("cannot decode image: %v", err)
		*detailBuf = (*detailBuf)[:0]
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategoryCorrupted,
			Confidence:  0.9,
			Description: "file cannot be decoded as a valid image",
		})
		result.Categories = append([]DetectionDetail(nil), *detailBuf...)
		return result
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	result.ImageSize = fmt.Sprintf("%dx%d", width, height)

	if width < 10 || height < 10 {
		result.IsSafe = false
		result.SafetyLevel = Suspicious
		result.Score = 0.4
		*detailBuf = (*detailBuf)[:0]
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategoryCorrupted,
			Confidence:  0.7,
			Description: fmt.Sprintf("image dimensions too small (%dx%d), possibly corrupted or placeholder", width, height),
		})
		result.Categories = append([]DetectionDetail(nil), *detailBuf...)
		return result
	}

	_ = format

	skinRatio := analyzeSkinPixels(img)

	*detailBuf = (*detailBuf)[:0]
	var score float64

	if skinRatio > 0.65 {
		score = 0.2
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategorySkinExposure,
			Confidence:  skinRatio,
			Description: fmt.Sprintf("high skin-tone pixel ratio detected (%.1f%%), content may be inappropriate", skinRatio*100),
		})
	} else if skinRatio > 0.45 {
		score = 0.5
		*detailBuf = append(*detailBuf, DetectionDetail{
			Category:    CategorySkinExposure,
			Confidence:  skinRatio,
			Description: fmt.Sprintf("moderate skin-tone pixel ratio detected (%.1f%%), content requires review", skinRatio*100),
		})
	} else {
		score = 0.95
	}

	if len(*detailBuf) > 0 {
		result.Categories = append([]DetectionDetail(nil), *detailBuf...)
	}
	result.Score = score

	if score >= 0.8 {
		result.IsSafe = true
		result.SafetyLevel = Safe
	} else if score >= 0.4 {
		result.IsSafe = false
		result.SafetyLevel = Suspicious
	} else {
		result.IsSafe = false
		result.SafetyLevel = Unsafe
	}

	return result
}

func analyzeSkinPixels(img image.Image) float64 {
	bounds := img.Bounds()
	totalPixels := 0
	skinPixels := 0

	stepX := 1
	stepY := 1
	if bounds.Dx() > 500 {
		stepX = bounds.Dx() / 500
	}
	if bounds.Dy() > 500 {
		stepY = bounds.Dy() / 500
	}

	for y := bounds.Min.Y; y < bounds.Max.Y; y += stepY {
		for x := bounds.Min.X; x < bounds.Max.X; x += stepX {
			r, g, b, _ := img.At(x, y).RGBA()
			ri := r >> 8
			gi := g >> 8
			bi := b >> 8

			totalPixels++

			if isSkinTone(uint8(ri), uint8(gi), uint8(bi)) {
				skinPixels++
			}
		}
	}

	if totalPixels == 0 {
		return 0
	}
	return float64(skinPixels) / float64(totalPixels)
}

func isSkinTone(r, g, b uint8) bool {
	if r < 60 || g < 40 || b < 20 {
		return false
	}
	if r <= g {
		return false
	}
	if r <= b {
		return false
	}
	if int(r)-int(g) < 15 {
		return false
	}
	maxDiff := max(int(r), int(g), int(b)) - min(int(r), int(g), int(b))
	if maxDiff < 15 {
		return false
	}
	ri := int(r)
	if ri > 220 && int(g) > 180 && int(b) > 150 {
		return true
	}
	if ri > 95 && int(g) > 40 && int(b) > 20 &&
		ri > int(g) && ri > int(b) &&
		(ri-int(g)) > 15 &&
		max(int(r), int(g), int(b))-min(int(r), int(g), int(b)) > 15 {
		return true
	}
	return false
}

func GetImageBase64(imagePath string) (string, error) {
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
