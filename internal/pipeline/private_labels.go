package pipeline

import (
	"strings"

	"golang.org/x/text/cases"
	"vansail-ip-atlas/internal/via3"
)

// Public labels can coincide with private catalog identifiers even when a
// separate publisher reported them as genuine geography or network identity.
// Remove the entire ambiguous label before any public frame or dictionary is
// written. Other fields on that same record retain their independent evidence.
func (c *compiler) redactPrivateLabels(r *via3.PublicRecord) {
	if len(c.options.PrivateLabelValues) == 0 {
		return
	}
	// normalize has copied these payloads, so redaction cannot mutate source input.
	switch {
	case r.Geo != nil:
		r.Geo.Region = c.publicLabel(r.Geo.Region)
		r.Geo.City = c.publicLabel(r.Geo.City)
	case r.Network != nil:
		r.Network.Name = c.publicLabel(r.Network.Name)
		r.Network.Organization = c.publicLabel(r.Network.Organization)
		r.Network.ISP = c.publicLabel(r.Network.ISP)
	case r.ASNAggregate != nil:
		r.ASNAggregate.Name = c.publicLabel(r.ASNAggregate.Name)
		r.ASNAggregate.Organization = c.publicLabel(r.ASNAggregate.Organization)
	}
}

func (c *compiler) publicLabel(label string) string {
	if label == "" {
		return ""
	}
	forbidden, known := c.labelDecisions[label]
	if !known {
		folded := cases.Fold().String(label)
		for _, needle := range c.options.PrivateLabelValues {
			if needle != "" && strings.Contains(folded, needle) {
				forbidden = true
				break
			}
		}
		if c.labelDecisions == nil {
			c.labelDecisions = make(map[string]bool)
		}
		// The public geography stream can revisit a city millions of times. Bound
		// the per-compilation decision cache even for entirely distinct input labels.
		if len(c.labelDecisions) >= 8192 {
			clear(c.labelDecisions)
		}
		c.labelDecisions[label] = forbidden
	}
	if forbidden {
		return ""
	}
	return label
}
