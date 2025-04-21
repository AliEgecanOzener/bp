from file_inclusion import *
import sys
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web pentest tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inclusion_parser = subparsers.add_parser("inclusion", help="For File Inclusion tests.")

    inclusion_parser.add_argument("--url", required=True, help="Target URL (e.g., http://site.com/page=)")
    inclusion_parser.add_argument("--cookie", help="Optional cookie value")

    inclusion_parser.add_argument("--file", help="Target file path (e.g, /etc/passwd)")
    inclusion_parser.add_argument("--filter", action="store_true", help="It uses php://filter wrapper for read data contents.")

    inclusion_parser.add_argument("--data",action="store_true")

    inclusion_parser.add_argument("--input",action="store_true", help="It uses php://data for POST requests.")

    inclusion_parser.add_argument("--accesslog", action="store_true", help="Access log poisoning.")

    inclusion_parser.add_argument("--authlog", action="store_true", help="Authentication log poisoning.")
    inclusion_parser.add_argument("--sshport", type=int, help="SSH Port Number. (Default is 22).")

    inclusion_parser.add_argument("--traversal", action="store_true",
    help="Customizable directory traversal testing. For this module, URL must contain 'TARGET' placeholder  (e.g., https://somesite.com/test?page=TARGET)")
    inclusion_parser.add_argument("--depth", type=int, help="'../' depth. (Default: 2)")
    inclusion_parser.add_argument("--max_retries", type=int, default=10, help="Maximum number of retries for failed payloads (Default: 10)")
    inclusion_parser.add_argument("--delay_ms", type=int, help="Time in milliseconds between each test (Default: 300 ms)")
    inclusion_parser.add_argument("--stop_on_success", action="store_true", help="Stop after the first successful attempt. (Default: False)")
    inclusion_parser.add_argument("--extra_files", nargs="*", help="List of extra files to include for fuzzing")
    inclusion_parser.add_argument("--keyword", help="Keyword to search in the --extra_files parameter to determine success")
    inclusion_parser.add_argument("--target_os", default="unknown", help="Target operating system (unix/windows/unknown)")

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






