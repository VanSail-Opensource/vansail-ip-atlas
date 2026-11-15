package admission

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// validateRPKIClientExcerpt checks only the observed parser schema. It returns
// no normalized records, publication metadata or completeness proof. Original
// publisher totals stay unchanged and must exceed this explicitly partial set.
// Runtime intake never calls this function and still requires the complete body.
func validateRPKIClientExcerpt(ctx context.Context, input io.Reader, source Source, selected adapter, now time.Time) (int, error) {
	deny := errors.New("reviewed RPKI excerpt invalid")
	actual, supported := selectAdapter(source)
	if ctx == nil || input == nil || now.IsZero() || !supported || actual != selected || selected != rpkiClientJSON || source.Format != "json" || source.Parser.Version != 1 || source.URL != "https://console.rpki-client.org/rpki.json" || source.Publication.Kind != "embedded" || source.Publication.Locator != source.URL || source.Publication.Field != "metadata.buildtime" || source.Fixture.PayloadFormat != "rpki-client-excerpt" || source.Fixture.ContentEncoding != "" && source.Fixture.ContentEncoding != "identity" {
		return 0, deny
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, input}, (1<<20)+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 || uniqueJSON(data) != nil {
		return 0, deny
	}
	var excerpt struct {
		Schema   string            `json:"fixture_schema"`
		Metadata json.RawMessage   `json:"metadata"`
		Rows     []json.RawMessage `json:"roas"`
	}
	if strictJSON(data, &excerpt) != nil || excerpt.Schema != "rpki-client-observed-excerpt-v1" || len(excerpt.Metadata) > 64<<10 || len(excerpt.Rows) == 0 || len(excerpt.Rows) > 256 {
		return 0, deny
	}
	header, err := decodeRPKIClientHeader(excerpt.Metadata, now, 100_000_000)
	if err != nil || header.UniqueVRPs <= len(excerpt.Rows) {
		return 0, deny
	}
	for _, row := range excerpt.Rows {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(row) > 64<<10 {
			return 0, deny
		}
		vrp, err := decodeRPKIClientVRP(row)
		if err != nil || !header.BuiltAt.Before(vrp.ValidUntil) {
			return 0, deny
		}
	}
	return len(excerpt.Rows), nil
}
