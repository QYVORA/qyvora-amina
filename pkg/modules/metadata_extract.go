package modules

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Embedded document metadata extraction.
//
// The point of this module is that a filename lies. A file called
// "quarterly-report-final-v3.docx" discloses nothing about who typed it, which
// organisation saved it, or which machine last wrote it, and that information
// travels with the file every time it is shared. Extracting it is the only way
// the finding can be about the metadata rather than about the extension.
//
// Three container formats cover the overwhelming majority of what a developer
// or analyst actually shares:
//
//   - OOXML and ODF (docx, xlsx, pptx, odt) are ZIP archives with an XML part
//     holding the properties.
//   - PDF keeps document information in a dictionary, in plain text.
//   - PNG and JPEG keep EXIF and text chunks, in binary.
//
// Each reader is bounded. An archive is read from its central directory rather
// than decompressed, and a file larger than the bound is not opened at all,
// because a malformed or hostile document should cost this scan nothing.

// maxMetadataFileSize is the bound on a single document. Documents larger than
// this are reported as unexamined rather than opened.
const maxMetadataFileSize = 32 << 20

// metaField is one extracted metadata entry.
type metaField struct {
	// Key is the normalised property name, e.g. "author".
	Key string
	// Value is the property's value. It is an author or an organisation, both
	// of which this tool is required to report, so it is kept verbatim.
	Value string
}

// documentMetadata extracts embedded metadata from one file.
//
// It returns nil for formats it does not understand, which is reported as "no
// metadata found" rather than "clean": the report distinguishes the two by the
// support level the collector assigns.
func documentMetadata(path string) []metaField {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > maxMetadataFileSize {
		return nil
	}
	ext := strings.ToLower(pathExt(path))
	switch ext {
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub":
		return zipMetadata(path)
	case ".doc", ".xls", ".ppt":
		return oleMetadata(path)
	case ".pdf":
		return pdfMetadata(path)
	case ".png":
		return pngMetadata(path)
	case ".jpg", ".jpeg":
		return jpegMetadata(path)
	case ".tif", ".tiff":
		return tiffMetadataFromFile(path)
	}
	return nil
}

func pathExt(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i:]
	}
	return ""
}

// zipMetadata reads the OOXML and ODF property parts.
//
// The archive index is read from the file's tail, so an entry whose payload is
// gigabytes compressed is never decompressed unless it is one of the two small
// XML parts this reads.
func zipMetadata(path string) []metaField {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer func() { _ = r.Close() }()

	wanted := map[string]bool{
		"docProps/core.xml":   true,
		"docProps/app.xml":    true,
		"meta.xml":            true, // ODF
		"docProps/custom.xml": true,
	}
	var out []metaField
	for _, f := range r.File {
		if !wanted[f.Name] || f.UncompressedSize64 > 1<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := make([]byte, f.UncompressedSize64)
		n, _ := readFull(rc, buf)
		_ = rc.Close()
		out = append(out, xmlMetadata(string(buf[:n]))...)
	}
	return out
}

// xmlMetadata pulls known properties out of an OOXML or ODF property part.
//
// It matches on local element names rather than on namespace-qualified tags,
// because the two formats use different namespaces for the same concepts and a
// document may declare either.
func xmlMetadata(body string) []metaField {
	// Local names worth extracting, mapped to the report key.
	want := map[string]string{
		"creator":               "author",
		"lastModifiedBy":        "last_modified_by",
		"Company":               "company",
		"Manager":               "manager",
		"Application":           "application",
		"initialCreator":        "author",
		"meta:last_modified_by": "last_modified_by",
	}
	var out []metaField
	for local, key := range want {
		re := regexp.MustCompile(`(?s)<(?:[A-Za-z0-9_.\-]+:)?` + regexp.QuoteMeta(local) + `\b[^>]*>(.*?)</(?:[A-Za-z0-9_.\-]+:)?` + regexp.QuoteMeta(local) + `>`)
		for _, m := range re.FindAllStringSubmatch(body, 2) {
			v := cleanMetadataValue(m[1])
			if v == "" {
				continue
			}
			out = append(out, metaField{Key: key, Value: v})
			if len(out) > 8 {
				return out
			}
		}
	}
	return out
}

// oleMetadata extracts the author from a legacy OLE2 document.
//
// The legacy formats store the author in the SummaryInformation stream as
// UTF-16. Searching for the UTF-16 encoding of "Author" is a targeted scan of a
// container that has no parser worth writing, and it avoids decoding the stream
// structure to get one field.
func oleMetadata(path string) []metaField {
	buf, err := readHead(path, 8<<20)
	if err != nil || len(buf) == 0 {
		return nil
	}
	// The property key names are ASCII in the directory and UTF-16 in the
	// stream, so both encodings are searched.
	for _, needle := range []string{"Author", "LastAuthor", "Company", "Manager"} {
		key := "last_modified_by"
		switch needle {
		case "Author":
			key = "author"
		case "Company":
			key = "company"
		case "Manager":
			key = "manager"
		}
		if v := findUTF16Value(buf, needle); v != "" {
			return []metaField{{Key: key, Value: v}}
		}
	}
	return nil
}

// findUTF16Value locates a UTF-16LE string in a buffer and returns the
// UTF-16LE string that follows it.
func findUTF16Value(buf []byte, name string) string {
	// Search for the ASCII name first; the value follows as UTF-16.
	idx := bytesIndex(buf, []byte(name))
	if idx < 0 {
		// Otherwise the name itself may be UTF-16 encoded.
		idx = bytesIndex(buf, utf16LE(name))
		if idx < 0 {
			return ""
		}
	}
	// The value is UTF-16LE from here; take printable runs and return the
	// longest one, which is the property rather than the padding around it.
	best := ""
	for _, start := range []int{idx + len(name)*2, idx + len(name) + 8} {
		if start >= len(buf) {
			continue
		}
		run := utf16LERun(buf[start:], 256)
		if len(run) > len(best) {
			best = run
		}
	}
	return cleanMetadataValue(best)
}

// pdfMetadata reads the document information dictionary of a PDF.
func pdfMetadata(path string) []metaField {
	buf, err := readHead(path, 4<<20)
	if err != nil || len(buf) < 5 {
		return nil
	}
	if !strings.HasPrefix(string(buf[:5]), "%PDF-") {
		return nil
	}
	wanted := map[string]string{
		"Author":      "author",
		"Creator":     "application",
		"Producer":    "producer",
		"Company":     "company",
		"CreatorTool": "application",
	}
	var out []metaField
	for key, reportKey := range wanted {
		v := pdfValue(buf, "/"+key)
		if v == "" {
			continue
		}
		out = append(out, metaField{Key: reportKey, Value: v})
		if len(out) > 6 {
			return out
		}
	}
	return out
}

// pdfValue finds /Key followed by a literal string or a hex string.
//
// PDF strings are either parenthesised with backslash escapes, or hex encoded
// inside angle brackets. Both are read directly from the byte slice.
func pdfValue(buf []byte, key string) string {
	idx := bytesIndex(buf, []byte(key))
	if idx < 0 {
		return ""
	}
	rest := buf[idx+len(key):]
	// Skip whitespace between the key and its value.
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\r' || rest[i] == '\n' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) {
		return ""
	}
	switch rest[i] {
	case '(':
		var sb strings.Builder
		for j := i + 1; j < len(rest); j++ {
			c := rest[j]
			if c == '\\' && j+1 < len(rest) {
				j++
				switch rest[j] {
				case 'n':
					sb.WriteByte('\n')
				case 'r':
					sb.WriteByte('\r')
				case 't':
					sb.WriteByte('\t')
				default:
					sb.WriteByte(rest[j])
				}
				continue
			}
			if c == ')' {
				break
			}
			if c == '\n' || c == '\r' {
				break
			}
			sb.WriteByte(c)
			if sb.Len() > 512 {
				break
			}
		}
		return cleanMetadataValue(sb.String())
	case '<':
		var hex []byte
		for j := i + 1; j < len(rest) && len(hex) < 1024; j++ {
			c := rest[j]
			if c == '>' {
				break
			}
			if !isHexDigit(c) {
				return ""
			}
			hex = append(hex, c)
		}
		if len(hex)%2 != 0 {
			return ""
		}
		decoded := make([]byte, len(hex)/2)
		for j := 0; j < len(decoded); j++ {
			decoded[j] = hexByte(hex[j*2])<<4 | hexByte(hex[j*2+1])
		}
		// A UTF-16BE hex string has a BOM.
		if len(decoded) >= 2 && decoded[0] == 0xFE && decoded[1] == 0xFF {
			return cleanMetadataValue(utf16BERun(decoded[2:]))
		}
		return cleanMetadataValue(string(decoded))
	}
	return ""
}

// pngMetadata reads tEXt, iTXt and zTXt chunks.
func pngMetadata(path string) []metaField {
	buf, err := readHead(path, 8<<20)
	if err != nil || len(buf) < 8 {
		return nil
	}
	if string(buf[:8]) != "\x89PNG\r\n\x1a\n" {
		return nil
	}
	var out []metaField
	pos := 8
	for pos+8 <= len(buf) && len(out) < 8 {
		length := int(binary.BigEndian.Uint32(buf[pos:]))
		if length < 0 || length > 1<<20 || pos+12+length > len(buf) {
			break
		}
		typ := string(buf[pos+4 : pos+8])
		data := buf[pos+8 : pos+8+length]
		if length > 0 && data[len(data)-1] == 0 {
			data = data[:len(data)-1]
		}
		switch typ {
		case "tEXt":
			if k, v, ok := strings.Cut(string(data), "\x00"); ok {
				if key := pngKey(k); key != "" {
					out = append(out, metaField{Key: key, Value: cleanMetadataValue(v)})
				}
			}
		case "iTXt":
			// keyword \0 compressionFlag compressionMethod language \0 translated \0 text
			if i := strings.IndexByte(string(data), 0); i >= 0 {
				key := pngKey(string(data[:i]))
				rest := data[i+1:]
				// Skip the three single-byte fields, then two NUL-terminated
				// strings, leaving the text.
				if len(rest) > 2 {
					rest = rest[2:]
					if j := bytesIndexByte(rest, 0); j >= 0 {
						rest = rest[j+1:]
						if k := bytesIndexByte(rest, 0); k >= 0 {
							rest = rest[k+1:]
						}
						if key != "" {
							out = append(out, metaField{Key: key, Value: cleanMetadataValue(string(rest))})
						}
					}
				}
			}
		}
		pos += 12 + length
		if typ == "IEND" {
			break
		}
	}
	return out
}

// pngKey maps a PNG text chunk keyword onto a report key.
func pngKey(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "author", "artist", "creator":
		return "author"
	case "copyright":
		return "copyright"
	case "software", "application":
		return "application"
	case "comment", "description":
		return "comment"
	case "company":
		return "company"
	case "creation time":
		return "created"
	case "software_used":
		return "application"
	}
	return ""
}

// jpegMetadata reads the EXIF segment of a JPEG.
func jpegMetadata(path string) []metaField {
	buf, err := readHead(path, 8<<20)
	if err != nil || len(buf) < 4 || buf[0] != 0xFF || buf[1] != 0xD8 {
		return nil
	}
	pos := 2
	for pos+4 <= len(buf) {
		if buf[pos] != 0xFF {
			pos++
			continue
		}
		marker := buf[pos+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		if marker == 0xDA || marker == 0xD9 {
			// Start of scan or end of image: no more metadata segments.
			break
		}
		if pos+4 > len(buf) {
			break
		}
		size := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		if size < 2 || pos+2+size > len(buf) {
			break
		}
		seg := buf[pos+4 : pos+2+size]
		if marker == 0xE1 && len(seg) >= 6 && string(seg[:6]) == "Exif\x00\x00" {
			if fields := tiffMetadata(seg[6:]); len(fields) > 0 {
				return fields
			}
		}
		if marker == 0xFE {
			if out := jpegComment(seg); len(out) > 0 {
				return out
			}
		}
		pos += 2 + size
	}
	return nil
}

func jpegComment(seg []byte) []metaField {
	if len(seg) == 0 {
		return nil
	}
	if v := cleanMetadataValue(string(seg)); v != "" {
		return []metaField{{Key: "comment", Value: v}}
	}
	return nil
}

// tiffMetadata is a minimal TIFF/EXIF IFD0 reader.
//
// Only the string-valued tags that identify a person or an organisation are
// read. Anything else in an EXIF block — GPS coordinates, device serial numbers,
// timestamps — is deliberately ignored: this module reports who a document
// reveals, and a camera's serial number is a different subject with a
// different consent story.
func tiffMetadata(tiff []byte) []metaField {
	if len(tiff) < 8 {
		return nil
	}
	var order binary.ByteOrder
	switch {
	case tiff[0] == 'I' && tiff[1] == 'I':
		order = binary.LittleEndian
	case tiff[0] == 'M' && tiff[1] == 'M':
		order = binary.BigEndian
	default:
		return nil
	}
	magic := order.Uint16(tiff[2:4])
	var offset uint32
	switch magic {
	case 42:
		offset = order.Uint32(tiff[4:8])
	case 0x4F52, 0x5352:
		// BigTIFF. The 64-bit offsets are not followed; the string tags this
		// module wants live in the first IFD and are addressed the same way.
		if len(tiff) < 16 {
			return nil
		}
		offset = order.Uint32(tiff[8:12])
	default:
		return nil
	}

	if offset+2 > uint32(len(tiff)) {
		return nil
	}
	count := int(order.Uint16(tiff[offset : offset+2]))
	var out []metaField
	for i := 0; i < count; i++ {
		entry := offset + 2 + uint32(i)*12
		if entry+12 > uint32(len(tiff)) {
			break
		}
		tag := order.Uint16(tiff[entry : entry+2])
		key, ok := exifKey(tag)
		if !ok {
			continue
		}
		typ := order.Uint16(tiff[entry+2 : entry+4])
		num := int(order.Uint32(tiff[entry+4 : entry+8]))
		if num <= 0 || num > 4096 {
			continue
		}
		// Only ASCII (2) and UNDEFINED (7) carry the identity strings.
		if typ != 2 && typ != 7 {
			continue
		}
		var value []byte
		if num <= 4 {
			value = tiff[entry+8 : entry+8+uint32(num)]
		} else {
			valOff := order.Uint32(tiff[entry+8 : entry+12])
			if valOff+uint32(num) > uint32(len(tiff)) {
				continue
			}
			value = tiff[valOff : valOff+uint32(num)]
		}
		if v := cleanMetadataValue(strings.TrimRight(string(value), "\x00")); v != "" {
			out = append(out, metaField{Key: key, Value: v})
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

func exifKey(tag uint16) (string, bool) {
	switch tag {
	case 0x013B:
		return "author", true
	case 0x0131:
		return "application", true
	case 0x010E:
		return "description", true
	case 0x8298:
		return "copyright", true
	case 0x010F:
		return "manufacturer", true
	}
	return "", false
}

// tiffMetadataFromFile reads EXIF from a standalone TIFF.
func tiffMetadataFromFile(path string) []metaField {
	buf, err := readHead(path, 8<<20)
	if err != nil || len(buf) < 8 {
		return nil
	}
	if (buf[0] == 'I' && buf[1] == 'I' && buf[2] == 42) || (buf[0] == 'M' && buf[1] == 'M' && buf[2] == 0 && buf[3] == 42) {
		return tiffMetadata(buf)
	}
	return nil
}

// cleanMetadataValue normalises an extracted value and rejects the ones that
// are not disclosures.
//
// Application defaults, empty values and the placeholder strings that image
// editors write when they have nothing to say are the majority of what EXIF
// holds, and reporting them would bury the two fields that matter.
func cleanMetadataValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\x00")
	v = strings.TrimSpace(v)
	if v == "" || !utf8.ValidString(v) {
		return ""
	}
	if len(v) > 256 {
		v = v[:256]
	}
	if isPlaceholder(v) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "microsoft word", "microsoft office word", "microsoft excel",
		"microsoft powerpoint", "libreoffice", "openoffice.org",
		"adobe photoshop", "adobe acrobat", "sketch", "affinity photo",
		"gimp", "imagemagick", "exiftool", "canva", "figma",
		"windows photo editor", "picasa", "snapseed", "unknown",
		"samsung", "apple", "google", "samsung electronics":
		return ""
	}
	return v
}

// Small byte helpers. The standard library has bytes.Index and friends, but
// keeping them local documents the intent at each call site.
func bytesIndex(b, sub []byte) int { return indexBytes(b, sub) }

func indexBytes(b, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func bytesIndexByte(b []byte, c byte) int { return indexByte(b, c) }

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// utf16LE encodes an ASCII string as UTF-16LE.
func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// utf16LERun decodes a UTF-16LE run of printable characters, stopping at the
// first value that is not plausible text.
func utf16LERun(b []byte, maxChars int) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b) && sb.Len() < maxChars; i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		if u < 0x20 || (u >= 0x7F && u < 0xA0) {
			break
		}
		sb.WriteRune(rune(u))
	}
	return sb.String()
}

// utf16BERun decodes a UTF-16BE run.
func utf16BERun(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.BigEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		if u < 0x20 || (u >= 0x7F && u < 0xA0) {
			break
		}
		sb.WriteRune(rune(u))
	}
	return sb.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// readHead reads at most n bytes from the start of a file.
func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size > n {
		size = n
	}
	buf := make([]byte, size)
	read, err := f.Read(buf)
	if err != nil && read == 0 {
		return nil, err
	}
	return buf[:read], nil
}

// readFull fills buf from r, tolerating short reads.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
	return total, nil
}
