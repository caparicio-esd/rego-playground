package policy_01_test

import rego.v1

import data.policy_01

test_car_read_positive if {
	inp = {
		"method": "GET",
		"path": ["cars"],
		"user": "alice",
	}
	policy_01.allow with input as inp
}

test_car_read_negative if {
	inp = {
		"method": "POST",
		"path": ["nonexistent"],
		"user": "carlos",
	}
	not policy_01.allow with input as inp
}
