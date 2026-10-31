![Banner](banner.png)

# file-external-reference-checker
Identifies and validates external file references (e.g., links, imports, includes) within a file against a list of known safe origins. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowGuardAI/file-external-reference-checker`

## Usage
`python3 main.py <filepath> --safe-origins <origin> [more origins]`

The tool makes no network access. It lists references found in the file and compares their origins against the safe origins supplied.

Default patterns cover quoted href and src attributes, unquoted href and src attributes, srcset lists (every URL in the list is checked), and CSS url() values.

Origin comparison uses the parsed hostname in lower case, with the port handled separately: an explicit default port (80 for http, 443 for https) equals no port, so `https://example.com:443/a` and `https://EXAMPLE.com/a` both match the safe origin `example.com`, while a different host is still unsafe. Safe origins may be given as a bare host, a host with a port, or a full origin, and are parsed the same way.

Exit codes: exit 1 when any unsafe reference is found, when the input cannot be read, and when the input file is empty (a distinct nothing scanned line is logged). Exit 0 when the scan completes and every reference found is safe, or no references are found in a non-empty file.

## Parameters
- `filepath`: Path to the file to analyze (required, positional)
- `-h`: Show help message and exit
- `--safe-origins`: List of safe origins allowed for external references (required)
- `--reference-patterns`: List of regex patterns to identify external references
- `--log-level`: Set the logging level

## License
Copyright (c) ShadowGuardAI
