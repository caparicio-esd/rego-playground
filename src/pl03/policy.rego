package pl03

import rego.v1

default is_admin := false

is_admin if {
	some admin in data.admins
	input.user == admin
}

a := input.user
