// Package facts holds immutable public enum validation shared by compilers and
// readers. It contains no data-source identifiers or network lookup behavior.
package facts

import (
	"regexp"
	"strings"
)

// CountryValid accepts assigned ISO 3166-1 alpha-2 values, uppercase only.
// Unknown/pseudo values (including AA, ZZ and XK) remain absent in schema 3.
func CountryValid(value string) bool { return CountryCode(value) != "" }

// CountryCode returns the shared immutable spelling of an assigned country.
// This single table also backs validation of the two-letter serialized enum.
func CountryCode(value string) string {
	if len(value) != 2 || value[0]-'A' >= 26 || value[1]-'A' >= 26 {
		return ""
	}
	return assignedCountries[value[0]-'A'][value[1]-'A']
}

var assignedCountries = func() (codes [26][26]string) {
	for country := range strings.FieldsSeq(countryCodes) {
		codes[country[0]-'A'][country[1]-'A'] = country
	}
	return codes
}()

const countryCodes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"

// PublicASN uses the frozen schema-3 query/data acceptance ranges.
func PublicASN(asn uint32) bool {
	return asn != 0 && asn != 23456 && (asn < 64496 || asn >= 131072) && asn < 4_200_000_000
}

// A domain-like substring can occur inside punctuation in a descriptive token.
// Its shortest identifying suffix is a name character, a dot, a letter, and
// one more name character. This also recognizes the suffix of a longer domain.
var labelDomain = regexp.MustCompile(`[\p{L}\p{N}-]\.\p{L}[\p{L}\p{N}-]`)

// UnsafeLabelToken reports text that cannot be published in a descriptive label.
func UnsafeLabelToken(token string) bool {
	return strings.ContainsAny(token, `@:/\`) || strings.Contains(token, ".") && labelDomain.MatchString(token)
}
