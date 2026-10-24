// Package epss parses the FIRST EPSS daily score file.
//
// Source: https://epss.cyentia.com/epss_scores-current.csv.gz
//
// The file is gzip-compressed CSV. Its first line is a comment carrying the
// model version and the score date; then a header "cve,epss,percentile"; then
// one row per CVE.
package epss

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/feeds"
)

// Score is one CVE's exploitation probability.
type Score struct {
	CVE        string
	EPSS       float64 // probability 0..1
	Percentile float64
}

// Meta describes the file as a whole.
type Meta struct {
	ModelVersion string
	ScoreDate    time.Time // calendar date, UTC midnight
	Rows         int       // scores emitted
	Stats        feeds.Stats
}

// ParseGzip reads the gzip-compressed file as published.
func ParseGzip(r io.Reader, emit func(Score) error) (Meta, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return Meta{}, fmt.Errorf("epss: gzip: %w", err)
	}
	defer zr.Close()
	return Parse(zr, emit)
}

// Parse reads the decompressed CSV and calls emit for each valid row. It fails
// if the comment line or header is missing or the file has no rows: an empty
// score file must not silently overwrite scores that were loaded earlier.
// Rows that are malformed individually are counted in Stats.Skipped.
func Parse(r io.Reader, emit func(Score) error) (Meta, error) {
	var meta Meta
	br := bufio.NewReaderSize(r, 1<<20)
	sawHeader := false
	line := 0
	for {
		raw, err := br.ReadString('\n')
		if raw == "" && err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return meta, fmt.Errorf("epss: read: %w", err)
		}
		line++
		text := strings.TrimRight(raw, "\r\n")
		switch {
		case text == "":
		case strings.HasPrefix(text, "#"):
			for _, part := range strings.Split(strings.TrimPrefix(text, "#"), ",") {
				k, v, _ := strings.Cut(part, ":")
				switch strings.TrimSpace(k) {
				case "model_version":
					meta.ModelVersion = strings.TrimSpace(v)
				case "score_date":
					// "2026-10-23T12:00:28Z": the date is what matters; the
					// colons in the time make Cut keep the whole remainder.
					v = strings.TrimSpace(v)
					if len(v) >= 10 {
						if d, perr := time.Parse("2006-01-02", v[:10]); perr == nil {
							meta.ScoreDate = d
						}
					}
				}
			}
		case !sawHeader:
			if text != "cve,epss,percentile" {
				return meta, fmt.Errorf("epss: line %d: header is %q, want \"cve,epss,percentile\"", line, text)
			}
			sawHeader = true
		default:
			s, ok := parseRow(text)
			if !ok {
				meta.Stats.Skip("malformed row")
			} else {
				if err := emit(s); err != nil {
					return meta, err
				}
				meta.Rows++
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return meta, fmt.Errorf("epss: read: %w", err)
		}
	}
	if !sawHeader {
		return meta, errors.New("epss: no header line")
	}
	if meta.ScoreDate.IsZero() {
		return meta, errors.New("epss: comment line has no score_date")
	}
	if meta.Rows == 0 {
		return meta, errors.New("epss: no score rows")
	}
	meta.Stats.Advisories = meta.Rows
	return meta, nil
}

func parseRow(text string) (Score, bool) {
	parts := strings.Split(text, ",")
	if len(parts) != 3 || !feeds.IsCVE(parts[0]) {
		return Score{}, false
	}
	e, err1 := strconv.ParseFloat(parts[1], 64)
	p, err2 := strconv.ParseFloat(parts[2], 64)
	if err1 != nil || err2 != nil || e < 0 || e > 1 || p < 0 || p > 1 {
		return Score{}, false
	}
	return Score{CVE: parts[0], EPSS: e, Percentile: p}, true
}
