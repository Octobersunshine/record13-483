package detector

import (
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
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
}

type DetectionDetail struct {
	Category    DetectionCategory `json:"category"`
	Confidence  float64           `json:"confidence"`
	Description string            `json:"description"`
}

var allowedExtensions = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".bmp":  true,
	".gif":  true,
	".webp": true,
}

func Detect(imagePath string) DetectionResult {
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
		result.Categories = []DetectionDetail{{
			Category:    CategoryInvalidFormat,
			Confidence:  1.0,
			Description: fmt.Sprintf("file extension '%s' is not a supported image format", ext),
		}}
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
		result.Categories = []DetectionDetail{{
			Category:    CategoryCorrupted,
			Confidence:  1.0,
			Description: "image file is empty (0 bytes)",
		}}
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
		result.Categories = []DetectionDetail{{
			Category:    CategoryCorrupted,
			Confidence:  0.9,
			Description: "file cannot be decoded as a valid image",
		}}
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
		result.Categories = []DetectionDetail{{
			Category:    CategoryCorrupted,
			Confidence:  0.7,
			Description: fmt.Sprintf("image dimensions too small (%dx%d), possibly corrupted or placeholder", width, height),
		}}
		return result
	}

	_ = format

	skinRatio := analyzeSkinPixels(img)

	var details []DetectionDetail
	var score float64

	if skinRatio > 0.65 {
		score = 0.2
		details = append(details, DetectionDetail{
			Category:    CategorySkinExposure,
			Confidence:  skinRatio,
			Description: fmt.Sprintf("high skin-tone pixel ratio detected (%.1f%%), content may be inappropriate", skinRatio*100),
		})
	} else if skinRatio > 0.45 {
		score = 0.5
		details = append(details, DetectionDetail{
			Category:    CategorySkinExposure,
			Confidence:  skinRatio,
			Description: fmt.Sprintf("moderate skin-tone pixel ratio detected (%.1f%%), content requires review", skinRatio*100),
		})
	} else {
		score = 0.95
	}

	result.Categories = details
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
