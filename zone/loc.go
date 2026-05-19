package zone

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// LOC is the RR handler for LOC (RFC 1876).
//
// Wire format (§2): fixed 16 octets — VERSION(1) + SIZE(1) +
// HORIZ_PRE(1) + VERT_PRE(1) + LATITUDE(4) + LONGITUDE(4) + ALTITUDE(4).
//
// Latitude and Longitude are uint32 in thousandths of arc-seconds offset
// from the equator / prime meridian (2^31 = origin). Altitude is uint32
// in centimetres offset by 10,000,000 (=100,000 m below WGS-84).
//
// SIZE / HORIZ_PRE / VERT_PRE each encode `mantissa * 10^exponent`
// centimetres in a single octet (high nibble = mantissa, low nibble =
// exponent).
//
// Presentation format (§3):
//
//	d1 [m1 [s1.frac]] {N|S} d2 [m2 [s2.frac]] {E|W} alt[m]
//	  [siz[m] [hp[m] [vp[m]]]]
type LOC struct {
	rr *ResourceRecord

	Version   uint8
	Size      uint8 // encoded byte
	HorizPre  uint8 // encoded byte
	VertPre   uint8 // encoded byte
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

const (
	locEquator   uint32 = 1 << 31  // 2^31 — origin of LAT / LON axes
	locAltOffset int64  = 10000000 // 100,000 m in centimetres
)

// ParseLOC constructs a LOC handler from RR presentation form. Returns
// [ErrPresentationFormat] when the value cannot be parsed.
func ParseLOC(rr *ResourceRecord, value string) (*LOC, error) {
	tokens := strings.Fields(strings.TrimSpace(value))
	idx := 0

	lat, consumed, err := parseLOCCoordinate(tokens, idx, "N", "S")
	if err != nil {
		return nil, fmt.Errorf("%w: LOC latitude: %v", ErrPresentationFormat, err)
	}
	idx += consumed

	lon, consumed, err := parseLOCCoordinate(tokens, idx, "E", "W")
	if err != nil {
		return nil, fmt.Errorf("%w: LOC longitude: %v", ErrPresentationFormat, err)
	}
	idx += consumed

	if idx >= len(tokens) {
		return nil, fmt.Errorf("%w: LOC: missing altitude in %q", ErrPresentationFormat, value)
	}
	altMeters, err := parseLOCMeters(tokens[idx])
	if err != nil {
		return nil, fmt.Errorf("%w: LOC altitude %q: %v", ErrPresentationFormat, tokens[idx], err)
	}
	idx++
	altCm := int64(math.Round(altMeters*100)) + locAltOffset
	if altCm < 0 || altCm > math.MaxUint32 {
		return nil, fmt.Errorf("%w: LOC altitude out of range: %g m", ErrPresentationFormat, altMeters)
	}

	// RFC 1876 §3 defaults: size = 1 m, horiz_pre = 10000 m, vert_pre = 10 m.
	sizeMeters := 1.0
	hpMeters := 10000.0
	vpMeters := 10.0
	if idx < len(tokens) {
		v, err := parseLOCMeters(tokens[idx])
		if err != nil {
			return nil, fmt.Errorf("%w: LOC size %q: %v", ErrPresentationFormat, tokens[idx], err)
		}
		sizeMeters = v
		idx++
	}
	if idx < len(tokens) {
		v, err := parseLOCMeters(tokens[idx])
		if err != nil {
			return nil, fmt.Errorf("%w: LOC horiz_pre %q: %v", ErrPresentationFormat, tokens[idx], err)
		}
		hpMeters = v
		idx++
	}
	if idx < len(tokens) {
		v, err := parseLOCMeters(tokens[idx])
		if err != nil {
			return nil, fmt.Errorf("%w: LOC vert_pre %q: %v", ErrPresentationFormat, tokens[idx], err)
		}
		vpMeters = v
		idx++
	}

	return &LOC{
		rr:        rr,
		Version:   0,
		Size:      encodeLOCPrecision(sizeMeters),
		HorizPre:  encodeLOCPrecision(hpMeters),
		VertPre:   encodeLOCPrecision(vpMeters),
		Latitude:  lat,
		Longitude: lon,
		Altitude:  uint32(altCm),
	}, nil
}

// WireBody emits the fixed 16-octet RDATA.
func (l *LOC) WireBody(b *wire.Builder) error {
	b.AppendUint16(16)
	b.AppendUint8(l.Version)
	b.AppendUint8(l.Size)
	b.AppendUint8(l.HorizPre)
	b.AppendUint8(l.VertPre)
	b.AppendUint32(l.Latitude)
	b.AppendUint32(l.Longitude)
	b.AppendUint32(l.Altitude)
	return nil
}

// Clone returns a copy of l. All fields are value types so no deep copy
// is needed.
func (l *LOC) Clone() RecordHandler {
	cp := *l
	return &cp
}

// locFactory adapts [ParseLOC] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func locFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseLOC(rr, value)
	if err != nil {
		return nil
	}
	return h
}

// parseLOCCoordinate consumes `d [m [s.frac]] {posChar|negChar}` from
// tokens starting at startIdx. Returns the encoded uint32 (offset from
// 2^31) along with the number of tokens consumed.
//
// Mirrors the TS parser: degrees-only, degrees-minutes, and
// degrees-minutes-seconds forms are accepted; seconds may be fractional.
func parseLOCCoordinate(tokens []string, startIdx int, posChar, negChar string) (uint32, int, error) {
	idx := startIdx
	if idx >= len(tokens) {
		return 0, 0, fmt.Errorf("missing degrees")
	}
	degrees, err := strconv.Atoi(tokens[idx])
	if err != nil {
		return 0, 0, fmt.Errorf("degrees %q: %v", tokens[idx], err)
	}
	idx++

	var minutes int
	var seconds float64
	// Optional minutes.
	if idx < len(tokens) && tokens[idx] != posChar && tokens[idx] != negChar {
		m, err := strconv.Atoi(tokens[idx])
		if err == nil {
			minutes = m
			idx++
			// Optional seconds (may be fractional).
			if idx < len(tokens) && tokens[idx] != posChar && tokens[idx] != negChar {
				s, err := strconv.ParseFloat(tokens[idx], 64)
				if err == nil {
					seconds = s
					idx++
				}
			}
		}
	}

	if idx >= len(tokens) {
		return 0, 0, fmt.Errorf("missing direction indicator (%s or %s)", posChar, negChar)
	}
	dir := tokens[idx]
	idx++
	positive := dir == posChar
	if !positive && dir != negChar {
		return 0, 0, fmt.Errorf("expected %s or %s, got %q", posChar, negChar, dir)
	}

	// (deg*3600 + min*60 + sec) * 1000 — thousandths of an arc-second.
	totalMs := int64(math.Round((float64(degrees)*3600 + float64(minutes)*60 + seconds) * 1000))
	var wireVal int64
	if positive {
		wireVal = int64(locEquator) + totalMs
	} else {
		wireVal = int64(locEquator) - totalMs
	}
	if wireVal < 0 || wireVal > math.MaxUint32 {
		return 0, 0, fmt.Errorf("coordinate out of uint32 range")
	}
	return uint32(wireVal), idx - startIdx, nil
}

// parseLOCMeters parses an altitude / size / precision value, accepting
// an optional trailing 'm' suffix (e.g. "30m" or "100").
func parseLOCMeters(s string) (float64, error) {
	cleaned := strings.TrimSuffix(s, "m")
	return strconv.ParseFloat(cleaned, 64)
}

// encodeLOCPrecision encodes a metre value as an RFC 1876 §2
// mantissa-exponent byte: `(mantissa<<4) | exponent` where the value
// represents `mantissa * 10^exponent` centimetres.
//
// Zero / negative inputs encode as 0x00 (per the TS implementation).
// The mantissa saturates at 9; the exponent saturates at 9.
func encodeLOCPrecision(meters float64) uint8 {
	cm := int64(math.Round(meters * 100))
	if cm <= 0 {
		return 0
	}
	exp := 0
	for cm >= 10 && exp < 9 {
		cm = int64(math.Round(float64(cm) / 10))
		exp++
	}
	if cm > 9 {
		cm = 9
	}
	return uint8((cm << 4) | int64(exp))
}
