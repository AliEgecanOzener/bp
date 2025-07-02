from file_inclusion import *
from xss import *
import sys
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web pentest tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # File Inclusion
    inclusion_parser = subparsers.add_parser("inclusion", help="For File Inclusion tests.")

    inclusion_parser.add_argument("--url", required=True, help="Target URL (e.g., http://site.com/page=)")
    inclusion_parser.add_argument("--cookie", help="Optional cookie value")
    inclusion_parser.add_argument("--proxy",  default=None, help="Scan with a proxy (e.g., proxy=)")

    inclusion_parser.add_argument("--file", help="Target file path (e.g, /etc/passwd)")
    inclusion_parser.add_argument("--filter", action="store_true", help="Use php://filter to read file content.")

    inclusion_parser.add_argument("--data",action="store_true", help="Use PHP data:// wrapper to include plain text base64-encoded payloads. ")

    inclusion_parser.add_argument("--input",action="store_true", help="Use php://input for POST-based payloads.")

    inclusion_parser.add_argument("--accesslog", action="store_true", help="Access log poisoning.")

    inclusion_parser.add_argument("--authlog", action="store_true", help="Authentication log poisoning (SSH).")
    inclusion_parser.add_argument("--sshport", type=int, help="Target's SSH port number. (Default is 22).")

    inclusion_parser.add_argument("--traversal", action="store_true",
    help="Customizable directory traversal testing. For this module, URL must contain 'TARGET' placeholder  (e.g., https://somesite.com/test?page=TARGET)")
    inclusion_parser.add_argument("--depth", type=int, help="'../' depth. (Default: 2)")
    inclusion_parser.add_argument("--max_retries", type=int, default=10, help="Number of attempts to retry payloads that couldn't be sent (default: 10)")
    inclusion_parser.add_argument("--delay_ms", type=int, help="Time in milliseconds between each test (Default: 300 ms)")
    inclusion_parser.add_argument("--stop_on_success", action="store_true", help="Stop after the first successful attempt.")
    inclusion_parser.add_argument("--extra_files", nargs="*", help="List of extra files to include for fuzzing")
    inclusion_parser.add_argument("--keyword", help="Keyword to search in the --extra_files parameter to determine success")
    inclusion_parser.add_argument("--target_os", default="unknown", help="Target operating system (unix/windows/unknown)")

    # Cross Site Scripting (XSS)
    xss_parser = subparsers.add_parser("xss", help="For File Inclusion tests.")

    xss_parser.add_argument("--url", required=True, help="Target URL (e.g., http://site.com/page=index.php)")
    xss_parser.add_argument("--cookie", help="Optional cookie value")
    xss_parser.add_argument("-m", help="HTTP request method")
    xss_parser.add_argument("--headers", help="Injectable header. User-Agent, Referer, Cookie, etc. This must contain 'TARGET' placeholder. e.g., User-Agent: Mozilla/5.0 TARGET AppleWebKit/537.36, Cookie=sessionid=abc; username=TARGET")
    xss_parser.add_argument("--headers_all", action="store_true", help="Automatic header injection without specified HTTP headers.")

    xss_parser.add_argument("--data", help="GET or POST data. (e.g., username=test&password=test)")
    xss_parser.add_argument("-p", help="Target parameters (e.g., id,username,password")

    xss_parser.add_argument("--reflected", action="store_true", help="Check for Reflected XSS.")
    xss_parser.add_argument("--stored", action="store_true", help="Check for Stored XSS.")
    xss_parser.add_argument("--stored_urls", help="Enter the URL where the Stored XSS occurs")

    xss_parser.add_argument("--open_browser", action="store_true", help="Displays the page with injected parameters. ")
   

    args = parser.parse_args()

    if args.command == "inclusion":
        if args.filter:
           if not args.file:
              sys.exit(1)

           php_filter(args)

        if args.data:
            php_data_wrapper(args)

        if args.input:
            check_post_accept(args)

        if args.accesslog:
           access_log_poisoning(args)

        if args.authlog:
            auth_log_poisoning(args)

        if args.traversal:
            if args.extra_files and not args.keyword:
               print(colored("Please specify keyword ford extra file","red"))
               sys.exit(1)

            if "TARGET" not in args.url:
                print(colored("URL must contain 'TARGET' placeholder", "red"))
                sys.exit(1)

            path_traversal_check(args)

    if args.command == "xss":
        xss_scanning(args)
