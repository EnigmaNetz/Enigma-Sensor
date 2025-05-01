package processor

import (
	"context"
	"time"
)

// ZeekData represents processed Zeek format data
type ZeekData struct {
	Timestamp  time.Time
	SourceFile string
	Data       []byte
	Metadata   map[string]string
}

// Processor defines the interface for handling Zeek format data
type Processor interface {
	// Process handles incoming Zeek format data
	Process(ctx context.Context, data ZeekData) error

	// Validate checks if the data is valid Zeek format
	Validate(data ZeekData) error

	// Store persists the processed data
	Store(ctx context.Context, data ZeekData) error

	// Cleanup removes processed data based on retention policy
	Cleanup(ctx context.Context) error
}

// ProcessorConfig holds configuration for the processor
type ProcessorConfig struct {
	StorageDir         string
	RetentionDays      int
	CompressionEnabled bool
}
