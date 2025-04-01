import argparse
from termcolor import colored
from utils import *
from urllib.parse import quote
from file_inclusion import *
import time


def parse_args():
    parser = argparse.ArgumentParser(
        description="Security testing tool for path traversal, LFI, php://input, and log poisoning attacks.")

    parser.add_argument('--cookie', type=str, required=True, help="Cookie string for the target")
    parser.add_argument('--mode', type=int, required=True, choices=[1, 2, 3, 4, 5],
                        help="Choose the mode: 1) Log Poisoning, 2) php://filter, 3) php://input, 4) Path Traversal PoC, 5) LFI with Custom Payload File")
    return parser.parse_args()


def main():
    args = parse_args()  
    cookie = args.cookie
    mode = args.mode

    select_mode(cookie, mode)


if __name__ == '__main__':
    main()