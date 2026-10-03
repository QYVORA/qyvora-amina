// Package banner provides the canonical amina brand banner (ASCII art).
//
// The art below is the exact byte-for-byte content of the brand banner file
// amina-banner.txt kept in the tools repository root (next to the sibling
// tools' banner files). Every surface of the tool (console, reports) renders
// this banner.
//
// The motif is a heraldic shield bearing a keyhole, drawn as a scan outline: an
// assessment of what a machine reveals about its operator is, in the end, an
// inventory of what is locked away and what is not. The art is 54 columns wide
// and 22 rows tall on purpose — wide enough to read as an emblem, short enough
// that a 24-row terminal still has room left for findings.
package banner

// Art is the canonical AMINA brand ASCII art banner.
const Art = `
                ____________________________
               /                            \
              /                              \
             |                                |
             |            .--------.          |
             |           /          \         |
             |          |            |        |
             |          |    .--.    |        |
             |          |   /    \   |        |
             |          |   |    |   |        |
             |          |   \    /   |        |
             |          |    '--'    |        |
             |           \  .----.  /         |
             |            \/      \/          |
             |             |      |           |
             |             |      |           |
             |             |      |           |
             |             |      |           |
             |              \    /            |
             |               \  /             |
             |                \/              |
              \                              /
               \                            /
                \__________________________/
`

// Width is the widest row of the art, used by the console to decide whether
// the banner fits before drawing it.
const Width = 54
