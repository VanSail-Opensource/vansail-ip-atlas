// Package intelligence compiles typed, already admitted evidence into public facts.
// Source admission and payload proof are separate trust boundaries; source metadata
// in these inputs is private and is never part of a public Result.
package intelligence

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Scope uint8

const (
	Exact Scope = iota
	ExplicitPrefix
	ASN
	Neighbors24
)

type Signal string

func CanonicalSignal(value Signal) (Signal, bool) {
	switch value {
	case "malware", "botnet", "c2", "abuse", "fraud", "scanner", "spam", "tor", "vpn", "proxy", "datacenter", "hosting":
		return value, true
	case "cloudflare_proxyip":
		return "proxy", true
	case "command_control":
		return "c2", true
	case "scanning":
		return "scanner", true
	default:
		return "", false
	}
}

type SignalPolicy struct {
	Beta, HalfLifeHours, Severity float64
	Reason                        uint32
	MergeInto                     Signal
}
type Policy struct {
	Signals                                  map[Signal]SignalPolicy
	Order                                    []Signal
	Weights                                  [4]float64
	Specificity                              [3]float64
	SubscriptionSpecificity                  float64
	MinimumFamilies                          int
	MaxAge, SubscriptionAge, FutureTolerance time.Duration
	GeoMargin                                float64
	GeoSupport                               [2]int
}

// LoadPolicy projects numeric values from the closed, versioned scoring contract.
// The complete five-file schema validator is also required before any release.
func LoadPolicy(r io.Reader) (Policy, error) {
	data, err := io.ReadAll(io.LimitReader(r, (2<<20)+1))
	if err != nil {
		return Policy{}, err
	}
	if len(data) > 2<<20 {
		return Policy{}, errors.New("scoring YAML exceeds 2 MiB")
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return Policy{}, err
	}
	var tail yaml.Node
	if err := decoder.Decode(&tail); err != io.EOF {
		return Policy{}, errors.New("one scoring document required")
	}
	if err := validateYAML(&doc, 0); err != nil {
		return Policy{}, err
	}
	if len(doc.Content) != 1 {
		return Policy{}, errors.New("scoring mapping required")
	}
	root := doc.Content[0]
	var version int
	var model string
	if err := yamlField(root, "schema_version").Decode(&version); err != nil || version != 3 {
		return Policy{}, errors.New("unsupported scoring schema")
	}
	if err := yamlField(root, "model_id").Decode(&model); err != nil || model != "via-risk-v3-contract-1" {
		return Policy{}, errors.New("unsupported scoring model")
	}
	p := Policy{Signals: make(map[Signal]SignalPolicy), MaxAge: 720 * time.Hour, SubscriptionAge: 168 * time.Hour}
	category := yamlField(root, "category_evidence")
	var categoryFormula, layerFormula string
	_ = yamlField(category, "formula").Decode(&categoryFormula)
	_ = yamlField(yamlField(root, "layers"), "formula").Decode(&layerFormula)
	if categoryFormula != "e(d,f)=max_{i in independent family f}(reliability_i*severity_i*specificity_i*2^(-age_hours_i/half_life_hours_d))" || layerFormula != "R=clamp(0,1,0.55*R_exact+0.18*R_prefix+0.15*C_asn*R_asn+0.12*C24*R24)" {
		return Policy{}, errors.New("unsupported scoring formula amendment")
	}
	signals := yamlField(category, "signals")
	if signals.Kind != yaml.MappingNode {
		return Policy{}, errors.New("signals required")
	}
	for i := 0; i < len(signals.Content); i += 2 {
		name, node := Signal(signals.Content[i].Value), signals.Content[i+1]
		var raw struct {
			Beta     float64 `yaml:"beta"`
			HalfLife float64 `yaml:"half_life_hours"`
			Severity float64 `yaml:"severity"`
			Reason   string  `yaml:"public_reason"`
			Merge    Signal  `yaml:"merge_into"`
		}
		if err := node.Decode(&raw); err != nil {
			return Policy{}, err
		}
		bit, ok := reasonBit(raw.Reason)
		if !ok {
			return Policy{}, errors.New("unknown risk reason")
		}
		p.Signals[name] = SignalPolicy{raw.Beta, raw.HalfLife, raw.Severity, bit, raw.Merge}
		p.Order = append(p.Order, name)
	}
	weights := yamlField(yamlField(root, "layers"), "weights")
	for i, key := range []string{"exact", "explicit_prefix", "asn", "neighbors24"} {
		if err := yamlField(weights, key).Decode(&p.Weights[i]); err != nil {
			return Policy{}, err
		}
	}
	specificity := yamlField(category, "indicator_specificity")
	for i, key := range []string{"exact", "prefix", "asn"} {
		if err := yamlField(specificity, key).Decode(&p.Specificity[i]); err != nil {
			return Policy{}, err
		}
	}
	if err := yamlField(specificity, "proxy_subscription_literal_ip").Decode(&p.SubscriptionSpecificity); err != nil {
		return Policy{}, err
	}
	var tolerance float64
	if err := yamlField(category, "future_timestamp_tolerance_hours").Decode(&tolerance); err != nil {
		return Policy{}, err
	}
	p.FutureTolerance = time.Duration(tolerance * float64(time.Hour))
	if err := yamlField(yamlField(root, "coverage"), "min_independent_assessment_families").Decode(&p.MinimumFamilies); err != nil {
		return Policy{}, err
	}
	geo := yamlField(root, "geo_fusion")
	if err := yamlField(geo, "winning_margin").Decode(&p.GeoMargin); err != nil {
		return Policy{}, err
	}
	for i, key := range []string{"region_min_support_families", "city_min_support_families"} {
		if err := yamlField(geo, key).Decode(&p.GeoSupport[i]); err != nil {
			return Policy{}, err
		}
	}
	return p, p.Validate()
}

func yamlField(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	return &yaml.Node{}
}
func validateYAML(n *yaml.Node, depth int) error {
	if depth > 32 || n.Kind == yaml.AliasNode {
		return errors.New("bounded unaliased scoring YAML required")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Tag != "!!str" || seen[k.Value] {
				return errors.New("duplicate or non-string scoring key")
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) Validate() error {
	if len(p.Signals) == 0 || p.MinimumFamilies < 2 || p.MaxAge <= 0 || p.SubscriptionAge <= 0 || p.FutureTolerance < 0 {
		return errors.New("invalid scoring policy")
	}
	var total float64
	for _, w := range p.Weights {
		if !finite(w) || w < 0 || w > 1 {
			return errors.New("invalid layer weight")
		}
		total += w
	}
	if math.Abs(total-1) > 1e-12 {
		return errors.New("layer weights must sum to one")
	}
	for _, s := range p.Signals {
		if !finite(s.Beta) || s.Beta < 0 || !finite(s.HalfLifeHours) || s.HalfLifeHours <= 0 || !finite(s.Severity) || s.Severity < 0 || s.Severity > 1 {
			return errors.New("invalid signal policy")
		}
		if s.MergeInto != "" {
			if target, ok := p.Signals[s.MergeInto]; !ok || target.MergeInto != "" {
				return errors.New("unresolved signal alias")
			}
		}
	}
	seen := map[Signal]bool{}
	for _, signal := range p.Order {
		if _, ok := p.Signals[signal]; !ok || seen[signal] {
			return errors.New("invalid canonical signal order")
		}
		seen[signal] = true
	}
	if len(seen) != len(p.Signals) {
		return errors.New("canonical signal order incomplete")
	}
	for _, value := range append(p.Specificity[:], p.SubscriptionSpecificity) {
		if !finite(value) || value < 0 || value > 1 {
			return errors.New("invalid evidence specificity")
		}
	}
	if !finite(p.GeoMargin) || p.GeoMargin < 0 || p.GeoMargin > 1 || p.GeoSupport[0] < 2 || p.GeoSupport[1] < 2 {
		return errors.New("invalid geo support policy")
	}
	return nil
}

const (
	ReasonMalware uint32 = 1 << iota
	ReasonBotnet
	ReasonCommandControl
	ReasonAbuse
	ReasonFraud
	ReasonScanning
	ReasonSpam
	ReasonTor
	ReasonVPN
	ReasonProxy
	ReasonDatacenter
	ReasonHosting
	ReasonASNContext
	ReasonSubnetContext
)

func reasonBit(name string) (uint32, bool) {
	names := []string{"malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting", "asn_context", "subnet_context"}
	for i, s := range names {
		if s == name {
			return 1 << i, true
		}
	}
	return 0, false
}
func ReasonNames(bits uint32) []string {
	out := []string{}
	for _, s := range []string{"malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting", "asn_context", "subnet_context"} {
		bit, _ := reasonBit(s)
		if bits&bit != 0 {
			out = append(out, s)
		}
	}
	return out
}
func finite(f float64) bool   { return !math.IsNaN(f) && !math.IsInf(f, 0) }
func clamp(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// Evidence never crosses the public boundary. Current means P2 admission, rights,
// payload/schema proof, and dependency validation have already succeeded.
type Evidence struct {
	Family                             string
	Signal                             Signal
	Scope                              Scope
	Address                            netip.Addr
	Prefix                             netip.Prefix
	ASN                                uint32
	SourcePublishedAt, ItemPublishedAt time.Time
	Weight                             float64
	Current, SubscriptionLiteral       bool
}
type Coverage struct {
	Family            string
	Layer             Scope
	Prefix            netip.Prefix // explicit assessed extent, never inferred from absence
	ASN               uint32
	PublishedAt       time.Time
	Current, Complete bool
}
type OriginMapping struct {
	Prefix  netip.Prefix
	Origins []uint32
}
type LayerResult struct {
	Risk     float64
	Reasons  uint32
	Observed bool
	Families []string
}
type ASNContext struct {
	Risk, Confidence, Contribution float64
	Present                        bool
}
type QualityResult struct {
	Score         *uint8
	Confidence    string
	Reasons       uint32
	Contributions [4]*float64
}
type exactFact struct {
	layer            LayerResult
	positiveFamilies []string
}
type Engine struct {
	policy                  Policy
	now                     time.Time
	exact                   map[netip.Addr]exactFact
	prefix                  map[netip.Prefix][]Evidence
	asn                     map[uint32]ASNContext
	origins                 map[netip.Prefix][]uint32
	coverage                [4]map[netip.Prefix]map[string]struct{}
	asnCoverage             map[uint32]map[string]struct{}
	neighbors               map[netip.Prefix][]netip.Addr
	neighborPartialCoverage map[netip.Prefix]bool
}

// NewEngine recomputes all contexts from the surviving input set. Rebuilding from
// a withdrawn/stale set cannot leave a prior host's influence in any aggregate.
// Callers partition large inputs before invoking this bounded partition engine.
func NewEngine(p Policy, evidence []Evidence, coverage []Coverage, mapping []OriginMapping, now time.Time) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("explicit build clock required")
	}
	if len(evidence) > 2_000_000 || len(coverage) > 100_000 || len(mapping) > 2_000_000 {
		return nil, errors.New("partition record budget exceeded")
	}
	p.Signals = cloneSignals(p.Signals)
	p.Order = append([]Signal(nil), p.Order...)
	e := &Engine{policy: p, now: now, exact: map[netip.Addr]exactFact{}, prefix: map[netip.Prefix][]Evidence{}, asn: map[uint32]ASNContext{}, origins: map[netip.Prefix][]uint32{}, asnCoverage: map[uint32]map[string]struct{}{}, neighbors: map[netip.Prefix][]netip.Addr{}, neighborPartialCoverage: map[netip.Prefix]bool{}}
	for i := range e.coverage {
		e.coverage[i] = map[netip.Prefix]map[string]struct{}{}
	}
	for _, m := range mapping {
		for _, asn := range m.Origins {
			if !IsPublicASN(asn) {
				return nil, errors.New("reserved origin ASN")
			}
		}
		prefix, prefixErr := canonicalPrefix(m.Prefix)
		if prefixErr != nil {
			return nil, errors.New("invalid origin prefix")
		}
		key := prefix
		origins := append(e.origins[key], m.Origins...)
		sort.Slice(origins, func(i, j int) bool { return origins[i] < origins[j] })
		e.origins[key] = uniqueASNs(origins)
	}
	exacts := map[netip.Addr][]Evidence{}
	direct := map[uint32][]Evidence{}
	for _, v := range evidence {
		if !v.Current {
			continue
		}
		var canonical bool
		v.Signal, canonical = CanonicalSignal(v.Signal)
		if !canonical {
			return nil, errors.New("unknown signal")
		}
		if _, ok := p.Signals[v.Signal]; !ok {
			return nil, errors.New("unknown signal")
		}
		if v.Family == "" || !finite(v.Weight) || v.Weight < 0 || v.Weight > 100 {
			return nil, errors.New("invalid private evidence")
		}
		if v.SourcePublishedAt.IsZero() {
			return nil, errors.New("publication proof time required")
		}
		clock := v.SourcePublishedAt
		if !v.ItemPublishedAt.IsZero() && v.ItemPublishedAt.Before(clock) {
			clock = v.ItemPublishedAt
		}
		if v.SourcePublishedAt.After(now.Add(p.FutureTolerance)) || v.ItemPublishedAt.After(now.Add(p.FutureTolerance)) {
			return nil, errors.New("future publication quarantined")
		}
		expiry := v.SourcePublishedAt.Add(p.MaxAge)
		if v.SubscriptionLiteral {
			sub := clock.Add(p.SubscriptionAge)
			if sub.Before(expiry) {
				expiry = sub
			}
		}
		if !now.Before(expiry) {
			continue
		}
		switch v.Scope {
		case Exact:
			if v.Address.Zone() != "" {
				return nil, errors.New("zoned exact address rejected")
			}
			v.Address = v.Address.Unmap()
			if !v.Address.IsValid() || v.Address.Zone() != "" {
				return nil, errors.New("invalid exact address")
			}
			exacts[v.Address] = append(exacts[v.Address], v)
		case ExplicitPrefix:
			prefix, prefixErr := canonicalPrefix(v.Prefix)
			if prefixErr != nil {
				return nil, errors.New("invalid explicit prefix")
			}
			key := prefix
			e.prefix[key] = append(e.prefix[key], v)
		case ASN:
			if !IsPublicASN(v.ASN) {
				return nil, errors.New("invalid ASN evidence")
			}
			direct[v.ASN] = append(direct[v.ASN], v)
		default:
			return nil, errors.New("host indicators cannot claim contextual scope")
		}
	}
	addresses := make([]netip.Addr, 0, len(exacts))
	for addr := range exacts {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	type aggregate struct {
		mass     float64
		count    int
		families map[string]struct{}
	}
	aggregates := map[uint32]*aggregate{}
	for _, addr := range addresses {
		layer, err := p.layer(exacts[addr], now)
		if err != nil {
			return nil, err
		}
		e.exact[addr] = exactFact{layer, layer.Families}
		if layer.Risk > 0 {
			if addr.Is4() {
				key := netip.PrefixFrom(addr, 24).Masked()
				e.neighbors[key] = append(e.neighbors[key], addr)
			}
			for _, asn := range e.Origins(addr) {
				a := aggregates[asn]
				if a == nil {
					a = &aggregate{families: map[string]struct{}{}}
					aggregates[asn] = a
				}
				a.mass += layer.Risk
				a.count++
				for _, f := range layer.Families {
					a.families[f] = struct{}{}
				}
			}
		}
	}
	for asn, list := range direct {
		if aggregates[asn] == nil {
			aggregates[asn] = &aggregate{families: map[string]struct{}{}}
		}
		for _, v := range list {
			if v.Weight > 0 {
				aggregates[asn].families[v.Family] = struct{}{}
			}
		}
	}
	for asn, a := range aggregates {
		explicit, err := p.layer(direct[asn], now)
		if err != nil {
			return nil, err
		}
		diversity := math.Min(1, float64(len(a.families))/3)
		confidence := diversity * math.Min(1, float64(a.count)/64)
		risk := math.Max(explicit.Risk, (1-math.Exp(-a.mass/256))*diversity)
		e.asn[asn] = ASNContext{risk, confidence, p.Weights[2] * confidence * risk, true}
	}
	for _, v := range coverage {
		if !v.Current || !v.Complete {
			continue
		}
		if v.Family == "" || v.PublishedAt.IsZero() || v.PublishedAt.After(now.Add(p.FutureTolerance)) {
			return nil, errors.New("invalid complete coverage")
		}
		if !now.Before(v.PublishedAt.Add(p.MaxAge)) {
			continue
		}
		if v.Layer == ASN {
			if !IsPublicASN(v.ASN) {
				return nil, errors.New("ASN coverage target required")
			}
			addFamily(e.asnCoverage, v.ASN, v.Family)
			continue
		}
		prefix, prefixErr := canonicalPrefix(v.Prefix)
		if v.Layer > Neighbors24 || prefixErr != nil {
			return nil, errors.New("explicit coverage extent required")
		}
		addFamily(e.coverage[v.Layer], prefix, v.Family)
		if v.Layer == Neighbors24 && prefix.Addr().Is4() && prefix.Bits() > 24 {
			e.neighborPartialCoverage[netip.PrefixFrom(prefix.Addr(), 24).Masked()] = true
		}
	}
	return e, nil
}

func addFamily[K comparable](m map[K]map[string]struct{}, key K, f string) {
	if m[key] == nil {
		m[key] = map[string]struct{}{}
	}
	m[key][f] = struct{}{}
}
func cloneSignals(input map[Signal]SignalPolicy) map[Signal]SignalPolicy {
	out := make(map[Signal]SignalPolicy, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
func uniqueASNs(values []uint32) []uint32 {
	out := values[:0]
	for _, v := range values {
		if v != 0 && (len(out) == 0 || out[len(out)-1] != v) {
			out = append(out, v)
		}
	}
	return out
}
func (e *Engine) Origins(addr netip.Addr) []uint32 {
	if addr.Zone() != "" {
		return nil
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil
	}
	for bits := addr.BitLen(); bits >= 0; bits-- {
		if origins, ok := e.origins[netip.PrefixFrom(addr, bits).Masked()]; ok {
			return append([]uint32(nil), origins...)
		}
	}
	return nil
}
func (p Policy) layer(records []Evidence, now time.Time) (LayerResult, error) {
	type key struct {
		signal Signal
		family string
	}
	maximum := map[key]float64{}
	reasons := uint32(0)
	for _, v := range records {
		config := p.Signals[v.Signal]
		signal := v.Signal
		if config.MergeInto != "" {
			signal = config.MergeInto
			config = p.Signals[signal]
		}
		clock := v.SourcePublishedAt
		if !v.ItemPublishedAt.IsZero() && v.ItemPublishedAt.Before(clock) {
			clock = v.ItemPublishedAt
		}
		age := math.Max(0, now.Sub(clock).Hours())
		specificity := p.Specificity[v.Scope]
		if v.SubscriptionLiteral {
			specificity = p.SubscriptionSpecificity
		}
		contribution := v.Weight / 100 * config.Severity * specificity * math.Exp2(-age/config.HalfLifeHours)
		if !finite(contribution) {
			return LayerResult{}, errors.New("nonfinite observation")
		}
		k := key{signal, v.Family}
		if contribution > maximum[k] {
			maximum[k] = contribution
		}
		if contribution > 0 {
			reasons |= config.Reason
		}
	}
	families := map[string]struct{}{}
	mass := 0.0
	for _, signal := range p.Order {
		config := p.Signals[signal]
		if config.MergeInto != "" {
			continue
		}
		ordered := []string{}
		for k, value := range maximum {
			if k.signal == signal && value > 0 {
				ordered = append(ordered, k.family)
			}
		}
		sort.Strings(ordered)
		sum := 0.0
		for _, family := range ordered {
			sum += maximum[key{signal, family}]
			families[family] = struct{}{}
		}
		mass += config.Beta * sum
	}
	return LayerResult{1 - math.Exp(-mass), reasons, len(records) > 0, sortedFamilies(families)}, nil
}
func sortedFamilies(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
func intersect(sets ...map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	if len(sets) == 0 {
		return out
	}
	for f := range sets[0] {
		present := true
		for _, set := range sets[1:] {
			if _, ok := set[f]; !ok {
				present = false
				break
			}
		}
		if present {
			out[f] = struct{}{}
		}
	}
	return out
}
func (e *Engine) complete(layer Scope, addr netip.Addr) map[string]struct{} {
	if layer == Neighbors24 {
		if !addr.Is4() {
			return map[string]struct{}{}
		}
		prefix := netip.PrefixFrom(addr, 24).Masked()
		if !e.neighborPartialCoverage[prefix] {
			out := map[string]struct{}{}
			for bits := 24; bits >= 0; bits-- {
				for f := range e.coverage[layer][netip.PrefixFrom(addr, bits).Masked()] {
					out[f] = struct{}{}
				}
			}
			return out
		}
		var common map[string]struct{}
		for neighbor := prefix.Addr(); prefix.Contains(neighbor); neighbor = neighbor.Next() {
			if neighbor == addr {
				continue
			}
			set := e.coveringFamilies(layer, neighbor)
			if common == nil {
				common = set
			} else {
				common = intersect(common, set)
			}
			if len(common) == 0 {
				return common
			}
		}
		return common
	}
	return e.coveringFamilies(layer, addr)
}
func (e *Engine) coveringFamilies(layer Scope, addr netip.Addr) map[string]struct{} {
	out := map[string]struct{}{}
	minBits := addr.BitLen()
	for bits := minBits; bits >= 0; bits-- {
		for f := range e.coverage[layer][netip.PrefixFrom(addr, bits).Masked()] {
			out[f] = struct{}{}
		}
	}
	return out
}

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("invalid IP prefix")
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New("mapped prefix spans unrelated IPv6")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

func (e *Engine) NeighborContext(addr netip.Addr) ASNContext {
	if addr.Zone() != "" {
		return ASNContext{}
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return ASNContext{}
	}
	families := map[string]struct{}{}
	mass := 0.0
	count := 0
	for _, neighbor := range e.neighbors[netip.PrefixFrom(addr, 24).Masked()] {
		if neighbor == addr {
			continue
		}
		fact := e.exact[neighbor]
		mass += fact.layer.Risk
		count++
		for _, f := range fact.positiveFamilies {
			families[f] = struct{}{}
		}
	}
	risk := 1 - math.Exp(-16*mass/255)
	confidence := math.Min(1, float64(count)/16) * math.Min(1, float64(len(families))/3)
	return ASNContext{risk, confidence, e.policy.Weights[3] * confidence * risk, count > 0}
}
func (e *Engine) ASNContext(asn uint32) ASNContext { return e.asn[asn] }

func (e *Engine) Lookup(addr netip.Addr) (QualityResult, error) {
	if addr.Zone() != "" {
		return QualityResult{Confidence: "unrated"}, errors.New("zoned lookup address rejected")
	}
	addr = addr.Unmap()
	result := QualityResult{Confidence: "unrated"}
	if !addr.IsValid() || addr.Zone() != "" {
		return result, errors.New("invalid lookup address")
	}
	exact := e.exact[addr].layer
	exactFamilies := e.complete(Exact, addr)
	prefixFamilies := e.complete(ExplicitPrefix, addr)
	neighborFamilies := e.complete(Neighbors24, addr)
	prefixRecords := []Evidence{}
	for bits := addr.BitLen(); bits >= 0; bits-- {
		prefixRecords = append(prefixRecords, e.prefix[netip.PrefixFrom(addr, bits).Masked()]...)
	}
	// All records were frozen and decayed against the same explicit build clock.
	prefix, err := e.policy.layer(prefixRecords, e.buildClock())
	if err != nil {
		return result, err
	}
	result.Reasons = exact.Reasons | prefix.Reasons
	if exact.Observed || len(exactFamilies) > 0 {
		v := e.policy.Weights[0] * exact.Risk
		result.Contributions[0] = &v
	}
	if prefix.Observed || len(prefixFamilies) > 0 {
		v := e.policy.Weights[1] * prefix.Risk
		result.Contributions[1] = &v
	}
	origins := e.Origins(addr)
	asnSets := []map[string]struct{}{}
	maxContribution := 0.0
	asnPresent := false
	for _, asn := range origins {
		context := e.asn[asn]
		maxContribution = math.Max(maxContribution, context.Contribution)
		asnPresent = asnPresent || context.Present
		asnSets = append(asnSets, e.asnCoverage[asn])
	}
	asnFamilies := intersect(asnSets...)
	if asnPresent || len(asnFamilies) > 0 {
		result.Contributions[2] = &maxContribution
		if maxContribution > 0 {
			result.Reasons |= ReasonASNContext
		}
	}
	neighbor := e.NeighborContext(addr)
	if addr.Is4() && (neighbor.Present || len(neighborFamilies) > 0) {
		v := neighbor.Contribution
		result.Contributions[3] = &v
		if v > 0 {
			result.Reasons |= ReasonSubnetContext
		}
	}
	families := intersect(exactFamilies, prefixFamilies, asnFamilies, neighborFamilies)
	if !addr.Is4() || len(origins) == 0 || len(families) < e.policy.MinimumFamilies {
		return result, nil
	}
	risk := 0.0
	for _, contribution := range result.Contributions {
		if contribution == nil {
			return result, nil
		}
		risk += *contribution
	}
	score := uint8(math.Floor(100*(1-clamp(risk)) + .5))
	result.Score = &score
	if len(families) >= 4 {
		result.Confidence = "high"
	} else if len(families) == 3 {
		result.Confidence = "medium"
	} else {
		result.Confidence = "low"
	}
	return result, nil
}

// Kept private so no wall clock can be consulted during lookup.
func (e *Engine) buildClock() time.Time { return e.now }

// Millionths is the only public contribution quantization step.
func Millionths(value float64) (uint32, error) {
	if !finite(value) || value < 0 || value > 1 {
		return 0, fmt.Errorf("risk outside finite unit interval")
	}
	return uint32(math.Floor(value*1_000_000 + .5)), nil
}
