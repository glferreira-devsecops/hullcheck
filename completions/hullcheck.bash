_hullcheck() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local opts="--json --exit-zero --help --version -h -V"
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
  else
    COMPREPLY=( $(compgen -d -- "$cur") )
  fi
}
complete -F _hullcheck hullcheck
