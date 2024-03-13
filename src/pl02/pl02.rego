package pl02

import rego.v1

deny contains msg if {
	true
	msg := sprintf("%v, asdass", [2 == 2])
}

output["allow"] := true

output["adios"] := false if not _ok_todo

output["authz"] := 200 if 2 == 2

output["authz"] := 403 if not 2 == 2

_ok_todo if {
	not 2 == 3
}

split_image(str) := output if {
	image_version := split(str, ":")
	path := split(image_version[0], "/")
	output := [path[0], path[1], image_version[1]]
}

output["jarl"] := split_image("hooli.com/bla:1.3")

data_in := "hooli.com/bla:1.3"

allow if {
    pieces := split_image(data_in)
    pieces[0] == "hooli.com"
}

allow := false if {
    pieces := split_image(data_in)
    not pieces[0] == "hooli.com"
}
