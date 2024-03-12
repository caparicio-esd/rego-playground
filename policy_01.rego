package policy_01

import rego.v1

default allow := false

default user_is_employee := false

default user_is_manager := false

user_is_employee if {
	data[input.user].manager
}

user_is_manager if {
	user_is_employee
	not data[input.user].manager
}

allow if {
	user_is_manager
}

allow if {
	user_is_employee
}

allow if {
	input.method == "GET"
}
