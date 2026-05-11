// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import "encoding/xml"

// androidPrefs holds decoded Android SharedPreferences XML.
// Only <string> elements are captured; <int>, <boolean>, <long> elements are skipped.
// encoding/xml automatically decodes &quot; &amp; &lt; &gt; entities in chardata.
type androidPrefs struct {
	XMLName xml.Name    `xml:"map"`
	Strings []prefString `xml:"string"`
}

// prefString represents a single <string name="...">value</string> element.
type prefString struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// parseAndroidPrefsXML decodes an Android SharedPreferences XML document and
// returns a name→value map of all <string> elements. Non-string elements
// (<int>, <boolean>, <long>) are silently ignored.
//
// encoding/xml transparently decodes XML entity escaping (&quot; → "), which
// is essential since all JSON payloads inside these XML files use HTML entity
// encoding.
func parseAndroidPrefsXML(data []byte) (map[string]string, error) {
	var prefs androidPrefs
	if err := xml.Unmarshal(data, &prefs); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(prefs.Strings))
	for _, s := range prefs.Strings {
		m[s.Name] = s.Value
	}
	return m, nil
}
