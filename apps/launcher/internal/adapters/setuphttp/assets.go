package setuphttp

import _ "embed"

//go:embed assets/index.html
var embeddedIndex []byte

//go:embed assets/assets/index-qF1Dmln1.js
var embeddedJavaScript []byte

//go:embed assets/assets/style-CamGnmCt.css
var embeddedStyle []byte

type staticAsset struct {
	contentType string
	bytes       []byte
	accept      string
	mode        string
	destination string
}

var staticAssets = map[string]staticAsset{
	"/": {
		contentType: "text/html; charset=utf-8", bytes: embeddedIndex,
		accept: "text/html", mode: "navigate", destination: "document",
	},
	"/assets/index-qF1Dmln1.js": {
		contentType: "text/javascript; charset=utf-8", bytes: embeddedJavaScript,
		accept: "*/*", mode: "cors", destination: "script",
	},
	"/assets/style-CamGnmCt.css": {
		contentType: "text/css; charset=utf-8", bytes: embeddedStyle,
		accept: "text/css", mode: "no-cors", destination: "style",
	},
}
