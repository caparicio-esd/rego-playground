package pl03

import rego.v1

default is_admin := false

default is_admin_declared := false
default user_groups := []

user := input.user

is_admin if {
	some admin in data.admins2
	admin.user == input.user
	admin.level == 1
}

is_alice if {
	some i in data.admins
	i == input.user
}

has_admins_key if {
	data["admins2"]
}


user_groups := o if {
	is_admin
	o := input.groups
	o
}

is_in_engineering if {
	is_admin
	some i
	input.groups[i] == "engineering"
}

has_more_than_two_groups if {
	count(input.groups) >= 2
}

is_admin_declared if {
	data.admins2
}

is_in_cidr if {
	net.cidr_contains("127.0.0.1/26", "127.0.0.63")
	print("127.0.0.1/26")
}