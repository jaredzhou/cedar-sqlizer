package utils

import "slices"

func Intersect[T comparable](a []T, b []T) []T {
	var r []T
	for _, v := range a {
		if slices.Contains(b, v) {
			r = append(r, v)
		}
	}
	return r
}
