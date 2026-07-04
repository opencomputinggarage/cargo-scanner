package main

import (
	"fmt"
	"io"
)

var completionCommands = []string{
	"init", "scan", "sbom", "doctor", "runtime", "tools", "cache", "completion", "version", "help",
}

func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "completion requires one shell: bash, zsh, fish, powershell")
		return 2
	}
	switch args[0] {
	case "bash":
		writeBashCompletion(stdout)
	case "zsh":
		writeZshCompletion(stdout)
	case "fish":
		writeFishCompletion(stdout)
	case "powershell":
		writePowerShellCompletion(stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "unsupported shell %q; use bash, zsh, fish, or powershell\n", args[0])
		return 2
	}
	return 0
}

func writeBashCompletion(w io.Writer) {
	_, _ = fmt.Fprint(w, `_cargo_scanner_completions()
{
  local cur prev commands scan_opts tools_cmds runtime_cmds cache_cmds
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="init scan sbom doctor runtime tools cache completion version help"
  scan_opts="--scanner --config --runtime --docker-image --format --json --output --raw-output --sbom-output --recursive --include --exclude --fail-on --timeout"
  tools_cmds="path list doctor install update update-db uninstall"
  runtime_cmds="pull"
  cache_cmds="path clean"
  if [[ ${COMP_CWORD} == 1 ]]; then
    COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
    return 0
  fi
  case "${COMP_WORDS[1]}" in
    scan|sbom) COMPREPLY=( $(compgen -W "${scan_opts}" -- "${cur}") ) ;;
    tools) COMPREPLY=( $(compgen -W "${tools_cmds}" -- "${cur}") ) ;;
    runtime) COMPREPLY=( $(compgen -W "${runtime_cmds}" -- "${cur}") ) ;;
    cache) COMPREPLY=( $(compgen -W "${cache_cmds}" -- "${cur}") ) ;;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "${cur}") ) ;;
  esac
}
complete -F _cargo_scanner_completions cargo-scanner
`)
}

func writeZshCompletion(w io.Writer) {
	_, _ = fmt.Fprint(w, `#compdef cargo-scanner
_cargo_scanner() {
  local -a commands
  commands=(
    'init:write .cargo-scanner.yaml'
    'scan:scan an artifact'
    'sbom:generate an SBOM'
    'doctor:check or fix the environment'
    'runtime:manage Docker runtime images'
    'tools:manage scanner CLIs'
    'cache:manage cache'
    'completion:print shell completion'
    'version:print version'
  )
  _describe 'command' commands
}
_cargo_scanner "$@"
`)
}

func writeFishCompletion(w io.Writer) {
	for _, cmd := range completionCommands {
		_, _ = fmt.Fprintf(w, "complete -c cargo-scanner -f -n '__fish_use_subcommand' -a %s\n", cmd)
	}
	_, _ = fmt.Fprint(w, `complete -c cargo-scanner -n '__fish_seen_subcommand_from scan sbom' -l scanner -x -a 'grype trivy syft'
complete -c cargo-scanner -n '__fish_seen_subcommand_from scan sbom' -l runtime -x -a 'auto managed docker native'
complete -c cargo-scanner -n '__fish_seen_subcommand_from scan sbom' -l format -x -a 'text json sarif'
complete -c cargo-scanner -n '__fish_seen_subcommand_from doctor' -l fix
`)
}

func writePowerShellCompletion(w io.Writer) {
	_, _ = fmt.Fprint(w, `Register-ArgumentCompleter -Native -CommandName cargo-scanner -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = 'init','scan','sbom','doctor','runtime','tools','cache','completion','version','help'
  $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`)
}
