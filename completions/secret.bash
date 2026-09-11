_secret_complete() {
  local cur prev
  cur=${COMP_WORDS[COMP_CWORD]}
  prev=${COMP_WORDS[COMP_CWORD-1]}
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( $(compgen -W 'generate set import path check exec' -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == generate && $prev == generate ]]; then
    COMPREPLY=( $(compgen -W 'url hex base64 uuid' -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == set || ${COMP_WORDS[1]} == import ]]; then
    COMPREPLY=( $(compgen -W '--replace --stdin --env' -- "$cur") )
  fi
}
complete -F _secret_complete secret
