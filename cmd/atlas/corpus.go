package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"vansail-ip-atlas/internal/subscription"
	"vansail-ip-atlas/internal/via3"
)

var corpusStrata = []string{"ipv4_exact", "ipv4_lpm", "ipv6_exact", "ipv6_lpm", "moas", "sparse_asn", "dense_asn", "inherited", "unknown"}

type corpusQuery struct {
	Q       string `json:"q"`
	Stratum string `json:"stratum"`
}
type productionCorpus struct {
	FormatVersion    int           `json:"format_version"`
	GraphQuery       string        `json:"graph_query"`
	InteractionQuery string        `json:"interaction_query"`
	Mode             string        `json:"mode"`
	Queries          []corpusQuery `json:"queries"`
}

// Corpus labels come from verified actual indexes/answers. The graph population
// is selected with the very same TypeScript projection shipped in the browser.
func buildProductionCorpus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("corpus", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "reviewed code workspace")
	atlas := fs.String("atlas", "build-private/production-atlas", "qualified immutable atlas")
	out := fs.String("out", ".atlas-private/production-browser-corpus.json", "private corpus destination")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "current verification clock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock <= 0 {
		return errors.New("invalid corpus arguments")
	}
	root, err := resolveProductionRoot(*workspace)
	if err != nil {
		return err
	}
	destination, err := privateReceiptDestination(root, *out)
	if err != nil {
		return err
	}
	atlasRoot := rooted(root, *atlas)
	release, err := via3.OpenRelease(atlasRoot, func() int64 { return *clock })
	if err != nil {
		return err
	}
	if release.Manifest.Mode != "production" {
		return errors.New("production corpus requires a production release")
	}
	buckets := map[string][]string{}
	seen := map[string]map[string]bool{}
	for _, stratum := range corpusStrata {
		seen[stratum] = map[string]bool{}
	}
	add := func(stratum, q string) {
		if len(buckets[stratum]) < 1200 && !seen[stratum][q] {
			seen[stratum][q] = true
			buckets[stratum] = append(buckets[stratum], q)
		}
	}
	corpus := productionCorpus{FormatVersion: 1, Mode: "production", Queries: []corpusQuery{}}
	graphCommand := exec.CommandContext(ctx, "node", filepath.Join(root, "tools", "hosted", "corpus-graph.mjs"))
	graphIn, err := graphCommand.StdinPipe()
	if err != nil {
		return err
	}
	graphOut, err := graphCommand.StdoutPipe()
	if err != nil {
		return err
	}
	graphCommand.Stderr = io.Discard
	if err = graphCommand.Start(); err != nil {
		return errors.New("corpus requires the pinned Node graph projector")
	}
	defer func() { _ = graphIn.Close(); _ = graphCommand.Wait() }()
	graphEncoder := json.NewEncoder(graphIn)
	graphScanner := bufio.NewScanner(graphOut)
	graphScanner.Buffer(make([]byte, 4096), 64<<10)
	graphCandidates := 0
	objects := append([]via3.ObjectInfo(nil), release.Manifest.Objects...)
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Kind != objects[j].Kind {
			return objects[i].Kind < objects[j].Kind
		}
		return objects[i].SHA256 < objects[j].SHA256
	})
	for _, object := range objects {
		if err = ctx.Err(); err != nil {
			return err
		}
		data, err := readPrivateInput(ctx, filepath.Join(atlasRoot, "objects", object.SHA256+".via3"), via3.MaxFile-1)
		if err != nil || via3.Hash(data) != object.SHA256 {
			return errors.New("corpus object integrity failed")
		}
		shard, err := via3.Read(ctx, data)
		if err != nil {
			return err
		}
		if err = via3.ValidatePublicProfile(shard); err != nil {
			return err
		}
		for _, section := range []uint16{1, 8} {
			if object.Kind == 1 {
				continue
			} // Router partitions are not observed facts.
			rows, _ := shard.Rows(section)
			for offset := 0; offset+32 <= len(rows); offset += 32 {
				row := rows[offset : offset+32]
				prefix, exact, err := corpusPrefix(row)
				if err != nil {
					return err
				}
				queryAddr := prefix.Addr()
				if section == 8 {
					partition, err := netip.ParsePrefix(object.Partition)
					if err != nil || !prefix.Contains(partition.Addr()) {
						continue
					}
					queryAddr = partition.Addr()
				}
				if !exact && prefix.Contains(queryAddr.Next()) {
					queryAddr = queryAddr.Next()
				}
				if !subscription.Public(queryAddr) {
					continue
				}
				q := queryAddr.String()
				family := "ipv6"
				if queryAddr.Is4() {
					family = "ipv4"
				}
				stratum := family + "_lpm"
				if exact {
					stratum = family + "_exact"
				}
				if section == 8 {
					stratum = "inherited"
				}
				// Only network rows can establish MOAS; do not issue a complete
				// lookup for every geo/quality record while this stratum is sparse.
				moasCandidate := false
				if object.Kind == 4 && len(buckets["moas"]) < 1200 {
					moasCandidate = corpusNetworkMOAS(&shard, row)
				}
				need := len(buckets[stratum]) < 1200 || moasCandidate || object.Kind == 2 && queryAddr.Is4() && corpus.InteractionQuery == ""
				if !need {
					continue
				}
				// A candidate index row can be shadowed by a more specific row,
				// an exact record, or a local replacement for an inherited row.
				// Only label the path that this query actually exercises. Do this
				// after the bucket bounds to avoid lookups for unused candidates.
				if !corpusRowSelected(&shard, section, row, queryAddr) {
					continue
				}
				answer, err := release.Lookup(ctx, q)
				if err != nil {
					return err
				}
				add(stratum, q)
				if len(answer.BGP.Origins) > 1 {
					add("moas", q)
				}
				if corpus.InteractionQuery == "" && queryAddr.Is4() && answer.Geo != nil && answer.Geo.Latitude != nil && answer.Geo.Longitude != nil && answer.Geo.City != nil && (answer.Usage == nil || answer.Usage.Anycast == nil || !*answer.Usage.Anycast) {
					corpus.InteractionQuery = q
				}
			}
		}
		if object.Kind == 8 || object.Kind == 11 {
			rows, _ := shard.Rows(2)
			for offset := 0; offset+8 <= len(rows); offset += 8 {
				asn := binary.LittleEndian.Uint32(rows[offset:])
				q := "AS" + strconv.FormatUint(uint64(asn), 10)
				if len(buckets["dense_asn"]) >= 1200 && len(buckets["sparse_asn"]) >= 1200 && corpus.GraphQuery != "" {
					break
				}
				answer, err := release.Lookup(ctx, q)
				if err != nil {
					return err
				}
				for _, a := range answer.ASNs {
					if a.ASN != asn {
						continue
					}
					if a.PrefixCursor != nil || len(a.Prefixes) >= 256 {
						add("dense_asn", q)
					} else if len(a.Prefixes) > 0 && len(a.Prefixes) <= 16 {
						add("sparse_asn", q)
					}
				}
				if corpus.GraphQuery == "" && graphCandidates < 10000 && len(answer.BGP.Paths) >= 2 {
					graphCandidates++
					if err = graphEncoder.Encode(answer); err != nil {
						return errors.New("graph corpus projector failed")
					}
					if !graphScanner.Scan() {
						return errors.New("graph corpus projector stopped")
					}
					var projection struct {
						Nodes  int `json:"nodes"`
						Routes int `json:"routes"`
					}
					if json.Unmarshal(graphScanner.Bytes(), &projection) != nil {
						return errors.New("invalid graph population reply")
					}
					if projection.Nodes == 24 && projection.Routes >= 2 {
						corpus.GraphQuery = q
					}
				}
			}
		}
	}
	for _, q := range []string{"0.0.0.0", "10.0.0.1", "192.0.2.1", "::", "::1", "2001:db8::1"} {
		answer, err := release.Lookup(ctx, q)
		if err != nil {
			return err
		}
		if answer.Geo == nil && answer.Network == nil && answer.Usage == nil && answer.Quality == nil && len(answer.ASNs) == 0 && len(answer.BGP.Paths) == 0 {
			add("unknown", q)
		}
	}
	if corpus.InteractionQuery == "" || corpus.GraphQuery == "" {
		return errors.New("real corpus lacks map or 24-node graph population")
	}
	for _, stratum := range corpusStrata {
		if len(buckets[stratum]) == 0 {
			return fmt.Errorf("real corpus stratum unavailable: %s", stratum)
		}
		sort.Strings(buckets[stratum])
	}
	// Round-robin prevents a short hot/cold sample selecting only the first
	// address family. Small real strata may repeat; they are never fabricated.
	for i := 0; i < 10000; i++ {
		stratum := corpusStrata[i%len(corpusStrata)]
		pool := buckets[stratum]
		corpus.Queries = append(corpus.Queries, corpusQuery{pool[(i/len(corpusStrata))%len(pool)], stratum})
	}
	return writeJSON(destination, corpus)
}

// FindPrefix supplies the actual longest matching prefix. Resolve only the
// exact/local tie at that prefix, using the same documented index ordering.
func corpusRowSelected(shard *via3.Shard, section uint16, row []byte, address netip.Addr) bool {
	prefix, _, err := corpusPrefix(row)
	if err != nil {
		return false
	}
	_, selected, ok := shard.FindPrefix(address)
	if !ok || selected != prefix.String() {
		return false
	}
	for _, exact := range []bool{true, false} {
		if exact && prefix.Bits() != address.BitLen() {
			continue
		}
		key := via3.PrefixKey(prefix, exact, 0)
		for _, id := range []uint16{1, 8} {
			rows, width := shard.Rows(id)
			if width != 32 {
				continue
			}
			compare := func(candidate []byte) int {
				if candidate[0] != key[0] {
					return int(candidate[0]) - int(key[0])
				}
				if c := bytes.Compare(candidate[4:20], key[4:20]); c != 0 {
					return c
				}
				if candidate[1] != key[1] {
					return int(candidate[1]) - int(key[1])
				}
				return int(binary.LittleEndian.Uint16(candidate[2:4])) - int(binary.LittleEndian.Uint16(key[2:4]))
			}
			index := sort.Search(len(rows)/32, func(i int) bool { return compare(rows[i*32:(i+1)*32]) >= 0 })
			if index < len(rows)/32 && compare(rows[index*32:(index+1)*32]) == 0 {
				return id == section && bytes.Equal(rows[index*32:(index+1)*32], row)
			}
		}
	}
	return false
}

func corpusNetworkMOAS(shard *via3.Shard, row []byte) bool {
	if shard.Kind != 4 || len(row) != 32 {
		return false
	}
	record := shard.Record(binary.LittleEndian.Uint32(row[20:24]))
	return len(record) == 40 && binary.LittleEndian.Uint32(record[8:12]) > 1
}

func corpusPrefix(row []byte) (netip.Prefix, bool, error) {
	if len(row) != 32 {
		return netip.Prefix{}, false, errors.New("invalid corpus prefix row")
	}
	var octets [16]byte
	copy(octets[:], row[4:20])
	address := netip.AddrFrom16(octets)
	if row[0] == 4 {
		var v4 [4]byte
		copy(v4[:], row[16:20])
		address = netip.AddrFrom4(v4)
	} else if row[0] != 6 {
		return netip.Prefix{}, false, errors.New("invalid corpus address family")
	}
	prefix := netip.PrefixFrom(address, int(row[1]))
	flags := binary.LittleEndian.Uint16(row[2:4])
	if !prefix.IsValid() || prefix != prefix.Masked() || address.Is4In6() || flags > 1 || flags == 1 && prefix.Bits() != address.BitLen() || !bytes.Equal(row[24:32], make([]byte, 8)) || row[0] == 4 && !bytes.Equal(row[4:16], make([]byte, 12)) {
		return netip.Prefix{}, false, errors.New("invalid corpus prefix")
	}
	return prefix, flags == 1, nil
}
