package secret

import (
	"errors"
	"fmt"
	"io"
)

func runCompletion(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("completion requires bash, zsh, or fish")
	}
	definition, ok := completionDefinitions[args[0]]
	if !ok {
		return errors.New("completion requires bash, zsh, or fish")
	}
	_, err := fmt.Fprint(out, definition)
	return err
}

var completionDefinitions = map[string]string{
	"bash": bashCompletion,
	"zsh":  zshCompletion,
	"fish": fishCompletion,
}

const bashCompletion = `_secret_complete() {
  local cur prev
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( $(compgen -W 'generate set import path check exec completion version help -h --help --version' -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == generate && $prev == generate ]]; then
    COMPREPLY=( $(compgen -W 'url hex base64 uuid' -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == completion ]]; then
    COMPREPLY=( $(compgen -W 'bash zsh fish' -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == set || ${COMP_WORDS[1]} == import ]]; then
    COMPREPLY=( $(compgen -W '--replace --stdin --env' -- "$cur") )
  fi
}
complete -F _secret_complete secret
`

const zshCompletion = `#compdef secret

_secret() {
  local -a commands generate_types
  commands=(
    'generate:generate a random value'
    'set:store a single-line token'
    'import:store a credential file byte-for-byte'
    'path:print an existing secret path'
    'check:audit the secret store'
    'exec:expose a textual value to one child command'
    'completion:print shell completion definitions'
    'version:print the secret version'
    'help:show help'
  )
  generate_types=('url:URL-safe characters' 'hex:hexadecimal characters' 'base64:base64-encoded bytes' 'uuid:RFC 4122 version 4 UUID')
  if (( CURRENT == 2 )); then
    _arguments '-h[show help]' '--help[show help]' '--version[show version]' '1:command:->command'
    [[ $state == command ]] && _describe command commands
  elif [[ $words[2] == generate && CURRENT == 3 ]]; then
    _describe format generate_types
  elif [[ $words[2] == completion && CURRENT == 3 ]]; then
    _values shell bash zsh fish
  elif [[ $words[2] == set || $words[2] == import ]]; then
    _arguments '*: :_guard "^-" secret-name' '--replace[replace an existing secret]' '--stdin[read non-terminal stdin]' '--env=[register the file path]:variable'
  fi
}

_secret "$@"
`

const fishCompletion = `complete -c secret -f
complete -c secret -n '__fish_use_subcommand' -a generate -d 'Generate a random value'
complete -c secret -n '__fish_use_subcommand' -a set -d 'Store a single-line token'
complete -c secret -n '__fish_use_subcommand' -a import -d 'Store a credential file'
complete -c secret -n '__fish_use_subcommand' -a path -d 'Print an existing secret path'
complete -c secret -n '__fish_use_subcommand' -a check -d 'Audit the secret store'
complete -c secret -n '__fish_use_subcommand' -a exec -d 'Expose text to one child command'
complete -c secret -n '__fish_use_subcommand' -a completion -d 'Print shell completion definitions'
complete -c secret -n '__fish_use_subcommand' -a version -d 'Print the secret version'
complete -c secret -n '__fish_use_subcommand' -a help -d 'Show help'
complete -c secret -n '__fish_use_subcommand' -s h -l help -d 'Show help'
complete -c secret -n '__fish_use_subcommand' -l version -d 'Show version'
complete -c secret -n '__fish_seen_subcommand_from generate' -a 'url hex base64 uuid'
complete -c secret -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c secret -n '__fish_seen_subcommand_from set import' -l replace -d 'Replace an existing secret'
complete -c secret -n '__fish_seen_subcommand_from set import' -l stdin -d 'Read non-terminal stdin'
complete -c secret -n '__fish_seen_subcommand_from set import' -l env -r -d 'Register the file path'
`
