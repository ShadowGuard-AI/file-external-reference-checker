import argparse
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Identifies and validates external file references within a file against a list of known safe origins."
    )
    parser.add_argument("filepath", type=str, help="Path to the file to analyze.")
    parser.add_argument(
        "--safe-origins",
        type=str,
        nargs="+",
        required=True,
        help="List of safe origins (domains) allowed for external references.",
    )
    parser.add_argument(
        "--reference-patterns",
        type=str,
        nargs="+",
        default=[r"href=['\"](.*?)['\"]", r"src=['\"](.*?)['\"]", r"(?:href|src)\s*=\s*(?![\'\"])([^\s>]+)", r"srcset=['\"](.*?)['\"]", r"url\((.*?)\)"],
        help="List of regex patterns to identify external references. Defaults cover quoted and unquoted href and src attributes, srcset lists, and CSS url() values.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).  Default: INFO",
    )
    return parser


def validate_origin(url, safe_origins):
    """
    Validates if the origin of a URL is in the list of safe origins.

    Args:
        url (str): The URL to validate.
        safe_origins (list): A list of safe origins (domains).

    Returns:
        bool: True if the origin is safe, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        # A reference with no host is a relative path and is treated as safe by
        # definition here: it resolves against the page's own origin, whichever
        # that is. A protocol-relative reference does carry a host, so it goes
        # through the real check below.
        if not parsed_url.netloc:  # Handle relative paths - consider them potentially safe if no origin is specified
            return True
        return _origin_matches(parsed_url, safe_origins)
    except Exception as e:
        logging.error(f"Error parsing URL {url}: {e}")
        return False


DEFAULT_PORTS = {"http": 80, "https": 443}


def _parsed_origin(value):
    """Parse a URL or a bare origin into (hostname, scheme, explicit port)."""
    text = value.strip()
    if "://" in text:
        parsed = urlparse(text)
    else:
        parsed = urlparse("//" + text)
    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    return hostname, (parsed.scheme or "").lower(), port


def _origin_matches(parsed_url, safe_origins):
    host = (parsed_url.hostname or "").lower()
    if not host:
        return True
    scheme = (parsed_url.scheme or "").lower()
    try:
        # Reading .port raises ValueError on a malformed port, and that is
        # treated as an unsafe reference rather than a parse problem. A URL
        # whose port cannot be read should not sail through a safety check.
        explicit_port = parsed_url.port
    except ValueError:
        return False
    effective_port = explicit_port if explicit_port is not None else DEFAULT_PORTS.get(scheme)
    for origin in safe_origins:
    # Host matching is exact. A safe origin of example.com does not cover
    # cdn.example.com; subdomains have to be listed themselves. Ports are
    # normalised before comparing: a reference with no port counts as its
    # scheme's default, a safe origin with a scheme and no port means that
    # scheme's default, and a safe origin with an explicit port matches
    # only that port.
        safe_host, safe_scheme, safe_port = _parsed_origin(origin)
        if safe_host != host:
            continue
        if safe_port is not None:
            if safe_port == effective_port:
                return True
            continue
        if safe_scheme:
            # A safe origin named with a scheme and no port means that
            # scheme's default port.
            if DEFAULT_PORTS.get(safe_scheme) == effective_port:
                return True
            continue
        # A bare host with no port matches a reference on the default
        # port for its scheme (so :443 on https equals no port).
        if effective_port is None or effective_port == DEFAULT_PORTS.get(scheme):
            return True
    return False


def find_external_references(filepath, reference_patterns):
    """
    Finds external file references within a file using regex patterns.

    Args:
        filepath (str): The path to the file to analyze.
        reference_patterns (list): A list of regex patterns to search for.

    Returns:
        list: A list of external references found in the file.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    references = []
    for pattern in reference_patterns:
        try:
            matches = re.findall(pattern, content)
        except Exception as e:
            logging.warning(f"Error applying regex pattern '{pattern}': {e}")
            continue
        if "srcset" in pattern:
            for match in matches:
                # srcset values are comma separated candidate lists, and each entry's
                # first token is the URL, the rest is a width or density descriptor.
                # A data URI in a srcset contains commas of its own and gets split at
                # them; the fragments then fail or pass as relative references.
                for entry in match.split(","):
                    entry = entry.strip()
                    if entry:
                        references.append(entry.split()[0])
        else:
            # References are collected pattern by pattern and never deduplicated.
            # The same URL found by two patterns is reported twice, and the counts
            # in main describe pattern hits, not distinct references. A custom
            # pattern with more than one group makes findall return tuples, which
            # then fail origin parsing and are reported unsafe.
            references.extend(matches)
    return references


def main():
    """
    Main function to execute the file external reference checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)

    filepath = args.filepath
    safe_origins = args.safe_origins
    reference_patterns = args.reference_patterns

    # Input validation for file path
    file_path_obj = Path(filepath)
    if not file_path_obj.exists():
        logging.error(f"The specified file path '{filepath}' does not exist.")
        sys.exit(1)

    if file_path_obj.is_file() and file_path_obj.stat().st_size == 0:
        logging.error("Nothing scanned: file is empty.")
        sys.exit(1)

    # Input validation for safe origins (basic check for valid domain characters)
    for origin in safe_origins:
        if not re.match(r"^[a-zA-Z0-9.\-:/]+$", origin):
            logging.warning(f"Suspicious character in safe origin: '{origin}'.  Consider double-checking its validity.")

    logging.info(f"Analyzing file: {filepath}")
    logging.info(f"Safe origins: {safe_origins}")
    logging.debug(f"Reference patterns: {reference_patterns}")

    try:
        external_references = find_external_references(filepath, reference_patterns)
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        sys.exit(1)

    if not external_references:
        logging.info("No external references found.")
        return

    logging.info(f"Found {len(external_references)} external references.")

    unsafe_references = []
    for reference in external_references:
        if not validate_origin(reference, safe_origins):
            logging.warning(f"Unsafe external reference found: {reference}")
            unsafe_references.append(reference)
        else:
            logging.debug(f"Safe external reference: {reference}")

    if unsafe_references:
        print("Unsafe external references found:")
        for reference in unsafe_references:
            print(f"- {reference}")
        sys.exit(1)
    else:
        print("All external references are safe.")


if __name__ == "__main__":
    # Example usage:
    # python main.py example.html --safe-origins example.com trusted.net
    # python main.py example.html --safe-origins example.com trusted.net --reference-patterns "href=['\"](.*?)['\"]"
    # python main.py example.txt --safe-origins example.com --log-level DEBUG
    main()