# AWK search field version 1.0
BEGIN{ FS = "[[:blank:]]*[[]" } {
    for (i=1; i<=NF; ++i) {
       if (match($i, /^[_[:alnum:]]+: /) && substr($i, 1, RLENGTH-2) == fld) {
           print ( substr($i, RLENGTH+1) )
           next
       }
    }
}