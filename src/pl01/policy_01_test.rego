package pl01_test

import rego.v1

import data.pl01

test_car_read_positive if {
	inp = {
		"method": "GET",
		"path": ["cars"],
		"user": "alice",
	}
	pl01.allow with input as inp
}

test_car_read_negative if {
	inp = {
		"method": "POST",
		"path": ["nonexistent"],
		"user": "carlos",
	}
	not pl01.allow with input as inp
}
