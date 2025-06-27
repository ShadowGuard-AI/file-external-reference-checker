import argparse
import logging
import re
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
        default=[r"href=['\"](.*?)['\"]", r"src=['\"](.*?)['\"]", r"url\((.*?)\)"],
        help="List of regex patterns to identify external references.  Default: href=['\"](.*?)['\"] src=['\"](.*?)['\"] url\((.*?)\)",
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
        if not parsed_url.netloc:  # Handle relative paths - consider them potentially safe if no origin is specified
            return True
        return parsed_url.netloc in safe_origins
    except Exception as e:
        logging.error(f"Error parsing URL {url}: {e}")
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
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return []

    references = []
    for pattern in reference_patterns:
        try:
            matches = re.findall(pattern, content)
            references.extend(matches)
        except Exception as e:
            logging.warning(f"Error applying regex pattern '{pattern}': {e}")
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
        return

    # Input validation for safe origins (basic check for valid domain characters)
    for origin in safe_origins:
        if not re.match(r"^[a-zA-Z0-9.-]+$", origin):
            logging.warning(f"Suspicious character in safe origin: '{origin}'.  Consider double-checking its validity.")

    logging.info(f"Analyzing file: {filepath}")
    logging.info(f"Safe origins: {safe_origins}")
    logging.debug(f"Reference patterns: {reference_patterns}")

    external_references = find_external_references(filepath, reference_patterns)

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
    else:
        print("All external references are safe.")


if __name__ == "__main__":
    # Example usage:
    # python main.py example.html --safe-origins example.com trusted.net
    # python main.py example.html --safe-origins example.com trusted.net --reference-patterns "href=['\"](.*?)['\"]"
    # python main.py example.txt --safe-origins example.com --log-level DEBUG
    main()