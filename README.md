# certcheck

An X.509 certificate validator.

    Usage: java CertificateExpirationChecker [options] file [options...] [file...]

    Options take effect for all files specified on the command-line after the option has been set.

    Options:
     -a, --alias <alias>   Specify the alias of the certificate to test within a keystore.
     -c, --critical <days> Specify the number of days before expiration that will be considered 'critical'.
     -d, --debug           Print additional debug output.
         --dn <dn>         Specify the subject name of the certificate to test within a keystore.
     -E, --error-stdout    Print errors to stdout instead of stderr.
     -f, --file <file>     Explicitly state that the next argument will be a file (useful for odd filenames).
     -h, --help            Print this help message and exit.
     -m, --max      <days> Specify the maximum number of days a certificate may be valid from today.
     -o, --options <file>  Specify an options-file where sensitive things like passwords can be specified safely.
     -P, --provider <name> Specifies a security provider to be used (default=any supporting provider).
     -p, --password        Specify the password to be used for all keystores and files (DANGEROUS! Consider using -o).
     -q, --quiet           Do not print anything if all there are no errors or warnings.
     -r, --report          Report the types of keystores supported and exit.
     -s, --silent          Do out print any output; only return exit code.
     -v, --verbose         Print information about all certificates processed.
     -S, --special <name>  Check a special keystore with the specified name (e.g. Windows-MY, KeychainStore, etc.).
     -w, --warning <days>  Specify the number of days before expiration that will be considered 'warning'.
     --                    Indicate that this is the last option and the remainder of arguments are filenames.

## Building

Use Maven

    mvn package

