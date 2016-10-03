package re

import "regexp"

func GetNamedMatches(re *regexp.Regexp, s string, n int) []map[string]string {
	groupNames := re.SubexpNames()
	matches := re.FindAllStringSubmatch(s, n)

	if matches == nil {
		return nil
	}

	results := make([]map[string]string, len(matches))

	for matchIndex, match := range matches {
		groupResult := make(map[string]string)
		for pos, groupName := range groupNames {
			if groupName != "" {
				groupResult[groupName] = match[pos]
			}
		}

		results[matchIndex] = groupResult
	}

	return results
}
