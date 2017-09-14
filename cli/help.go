package cli

import "io/ioutil"

/***Variables***/

// main help page
var helpMainPageBytes, _ = ioutil.ReadFile("cli/help.txt")
var helpMainPage = string(helpMainPageBytes)

// base command help page
var helpCommandPage = `Command: {{ .Name }} - {{ .Usage }}
{{if .Subcommands}}SubCommands:
  {{range .Subcommands}}{{join .Names ", "}}{{"\t"}}{{.Usage}}
{{"  "}}{{end}}{{end}}{{"\r"}}{{if .Flags}}Flags:
  {{range .Flags}}{{.}}{{"\n  "}}{{end}}{{"\r"}}{{end}}`
