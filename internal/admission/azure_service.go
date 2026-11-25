package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const azureDetails = acquire.AzureServiceTagsDetailsURL
const azureEditionBase = "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/"
const azureLimit = 16 << 20

var errAzureEdition = errors.New("Azure service-tag edition invalid")

func azureSeedDay(url string) (time.Time, error) {
	name, ok := strings.CutPrefix(url, azureEditionBase+"ServiceTags_Public_")
	stamp, okSuffix := strings.CutSuffix(name, ".json")
	date, err := time.Parse("20060102", stamp)
	if !ok || !okSuffix || err != nil || date.Year() < 1970 || url != azureEditionBase+azureFilename(date) {
		return time.Time{}, errAzureEdition
	}
	return date, nil
}

func azureServiceSource(s Source) bool {
	_, err := azureSeedDay(s.URL)
	return err == nil && s.ID == intelligence.AzureServiceSourceID && s.Family == "microsoft-azure-appservice" &&
		s.Category == "infrastructure" && s.Scope == "exact_ip" && s.Coverage == "positive_only" &&
		s.Parser == (Parser{"azure-appservice-service-tag", "azure-service-tags-json-v1", 1}) &&
		s.Format == "json" && s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= azureLimit &&
		s.Publication == (Publication{"snapshot_metadata", azureDetails, "download.filename.date"}) &&
		fieldsEqual(s.Signals, "hosting") && fieldsEqual(s.PublicFields, "reason_flags") &&
		fieldsEqual(s.Fields, "name", "id", "properties.systemService", "properties.addressPrefixes") &&
		mappedFields(s, map[string]string{"properties.addressPrefixes": "reason_flags"})
}

type azureTag struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Properties struct {
		Change   uint32   `json:"changeNumber"`
		Region   *string  `json:"region"`
		RegionID *int     `json:"regionId"`
		Platform string   `json:"platform"`
		System   string   `json:"systemService"`
		Prefixes []string `json:"addressPrefixes"`
		Features []string `json:"networkFeatures"`
	} `json:"properties"`
}

// Only the exact global AppService entry describes inbound multitenant application
// addresses. Regional, management, outbound and unrelated service tags are ignored.
func readAzureEdition(ctx context.Context, r io.Reader) (intelligence.AzureServiceEdition, error) {
	var result intelligence.AzureServiceEdition
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, azureLimit+1))
	if err != nil {
		return result, err
	}
	var document struct {
		Change uint32     `json:"changeNumber"`
		Cloud  string     `json:"cloud"`
		Values []azureTag `json:"values"`
	}
	if len(data) > azureLimit || jsonv2.Unmarshal(data, &document, jsonv2.RejectUnknownMembers(true)) != nil || document.Cloud != "Public" || document.Change == 0 || len(document.Values) == 0 || len(document.Values) > 10000 {
		return result, errAzureEdition
	}
	result.ChangeNumber = document.Change
	result.PayloadHash = sha256.Sum256(data)
	for _, tag := range document.Values {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if tag.Name != "AppService" && tag.ID != "AppService" {
			continue
		}
		p := &tag.Properties
		if result.TagChangeNumber != 0 || tag.Name != "AppService" || tag.ID != "AppService" || p.Change == 0 || p.Region == nil || *p.Region != "" || p.RegionID == nil || *p.RegionID != 0 || p.Platform != "Azure" || p.System != "AzureAppService" || len(p.Prefixes) == 0 || len(p.Prefixes) > intelligence.MaxAzureServiceHosts {
			return result, errAzureEdition
		}
		result.TagChangeNumber = p.Change
		seen := map[netip.Prefix]bool{}
		for _, value := range p.Prefixes {
			prefix, e := netip.ParsePrefix(value)
			if e != nil || prefix.String() != value || prefix != prefix.Masked() || prefix.Addr().Is4In6() || !subscription.Public(prefix.Addr()) || seen[prefix] {
				return result, errAzureEdition
			}
			seen[prefix] = true
			if prefix.IsSingleIP() {
				result.Hosts = append(result.Hosts, prefix.Addr())
			}
		}
	}
	if result.TagChangeNumber == 0 || len(result.Hosts) == 0 {
		return result, errAzureEdition
	}
	slices.SortFunc(result.Hosts, netip.Addr.Compare)
	return result, nil
}

func parseAzureService(ctx context.Context, r io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	ed, err := readAzureEdition(ctx, r)
	if err != nil {
		return err
	}
	if len(ed.Hosts) > maximum {
		return errAzureEdition
	}
	for _, a := range ed.Hosts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Address: a, Scope: intelligence.Exact, Signal: "hosting", Family: s.Family, Weight: s.Weight, SourcePublishedAt: published, Current: true}}); err != nil {
			return err
		}
	}
	return nil
}

func azureFilename(day time.Time) string {
	return "ServiceTags_Public_" + day.Format("20060102") + ".json"
}

func azureListing(page []byte, now time.Time) (time.Time, int64, error) {
	var day time.Time
	// Only the official Download Center model can select an asset. Extract its
	// bounded JSON array, then independently pin the URL, name, version and size.
	marker := []byte("<script>window.__DLCDetails__=")
	if len(page) > 2<<20 || bytes.Count(page, marker) != 1 {
		return day, 0, errAzureEdition
	}
	_, rest, _ := bytes.Cut(page, marker)
	raw, _, found := bytes.Cut(rest, []byte("</script>"))
	if !found || uniqueJSON(raw) != nil {
		return day, 0, errAzureEdition
	}
	var model struct {
		View struct {
			Error string `json:"error"`
			Title string `json:"downloadTitle"`
			Files []struct {
				Name          string `json:"name"`
				URL           string `json:"url"`
				Version       string `json:"version"`
				Size          string `json:"size"`
				DatePublished string `json:"datePublished"`
			} `json:"downloadFile"`
		} `json:"dlcDetailsView"`
	}
	if err := jsonv2.Unmarshal(raw, &model); err != nil || model.View.Error != "" || model.View.Title != "Azure IP Ranges and Service Tags – Public Cloud" || len(model.View.Files) != 1 {
		return day, 0, errAzureEdition
	}
	files := model.View.Files
	f := files[0]
	base, ok := strings.CutPrefix(f.Name, "ServiceTags_Public_")
	stamp, ending := strings.CutSuffix(base, ".json")
	day, err := time.Parse("20060102", stamp)
	if err != nil || !ok || !ending || day.Year() < 1970 || day.After(now) || f.Name != azureFilename(day) || f.URL != azureEditionBase+f.Name || f.Version != day.Format("2006.01.02") {
		return time.Time{}, 0, errAzureEdition
	}
	pub, e := time.Parse("1/2/2006 3:04:05 PM", f.DatePublished)
	if e != nil || pub.Before(day) || pub.After(now.Add(24*time.Hour)) {
		return time.Time{}, 0, errAzureEdition
	}
	size, e := strconv.ParseInt(f.Size, 10, 64)
	if e != nil || size <= 0 || size > azureLimit || strconv.FormatInt(size, 10) != f.Size {
		return time.Time{}, 0, errAzureEdition
	}
	return day, size, nil
}

func (e *Engine) fetchAzureService(ctx context.Context, payload string, s Source, now time.Time) (*intelligence.AzureServiceProof, error) {
	dir := filepath.Dir(payload)
	meta := filepath.Join(dir, "azure-publication")
	if _, err := e.fetch.Fetch(ctx, azureDetails, meta, 2<<20); err != nil {
		return nil, err
	}
	page, err := boundedFile(ctx, meta, 2<<20)
	if err != nil {
		return nil, err
	}
	day, expected, err := azureListing(page, now)
	if err != nil {
		return nil, err
	}
	seed, err := azureSeedDay(s.URL)
	if err != nil || day.Before(seed) || !now.Before(day.Add(s.MaxAge)) {
		return nil, errAzureEdition
	}
	proof := &intelligence.AzureServiceProof{Version: 1, IndexHash: sha256.Sum256(page)}
	for i := 0; i < 3; i++ {
		date := day.Add(-time.Duration(i) * 7 * 24 * time.Hour)
		dest := payload
		if i > 0 {
			dest = filepath.Join(dir, "azure-prior-"+strconv.Itoa(i))
		}
		raw, err := e.fetch.Fetch(ctx, azureEditionBase+azureFilename(date), dest, s.MaxCompressedBytes)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(dest)
		if err != nil {
			return nil, err
		}
		ed, parseErr := readAzureEdition(ctx, file)
		closeErr := file.Close()
		if parseErr != nil || closeErr != nil || raw.SHA256 != hashString(ed.PayloadHash) || raw.LastModified.IsZero() || raw.LastModified.After(now) || i == 0 && raw.Bytes != expected {
			return nil, errAzureEdition
		}
		ed.Day = date
		ed.LastModified = raw.LastModified.UTC()
		proof.Editions = append(proof.Editions, ed)
		if i > 0 && !date.Add(7*24*time.Hour).After(now) && !ed.LastModified.Add(7*24*time.Hour).After(now) {
			break
		}
	}
	_, err = proof.Eligible(now, day, proof.Editions[0].PayloadHash)
	return proof, err
}
