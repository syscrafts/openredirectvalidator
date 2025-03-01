#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
import sys
import socket
from aiohttp import ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects
from tqdm import tqdm
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List

# Color constants
LIGHT_GREEN = '\033[92m'  # Light Green
DARK_GREEN = '\033[32m'   # Dark Green
ENDC = '\033[0m'          # Reset to default color

async def load_payloads(payloads_file=None):
    # Use 'payloads.txt' as default if no file is specified
    file_to_read = payloads_file if payloads_file else "payloads.txt"
    try:
        with open(file_to_read) as f:
            return [line.strip() for line in f if line.strip()]  # Skip empty lines
    except FileNotFoundError:
        print(f"Error: Payload file '{file_to_read}' not found.")
        sys.exit(1)

def fuzzify_url(url: str, keyword: str) -> str:
    if keyword in url:
        return url
    parsed_url = urlparse(url)
    params = parse_qsl(parsed_url.query)
    fuzzed_params = [(k, keyword) for k, _ in params]
    fuzzed_query = urlencode(fuzzed_params)
    fuzzed_url = urlunparse(
        [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment])
    return fuzzed_url

def load_urls() -> List[str]:
    urls = []
    for line in sys.stdin:
        url = line.strip()
        fuzzed_url = fuzzify_url(url, "FUZZ")
        urls.append(fuzzed_url)
    return urls

async def fetch_url(session, url):
    try:
        async with session.head(url, allow_redirects=True, timeout=10) as response:
            return response
    except (ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects, UnicodeDecodeError, socket.gaierror, asyncio.exceptions.TimeoutError):
        return None

async def process_url(semaphore, session, url, payloads, keyword, pbar):
    async with semaphore:
        for payload in payloads:
            filled_url = url.replace(keyword, payload)
            response = await fetch_url(session, filled_url)
            if response and response.history and "-->" in " --> ".join(str(r.url) for r in response.history):
                locations = " --> ".join(str(r.url) for r in response.history)
                tqdm.write(f'{DARK_GREEN}[FOUND]{ENDC} {LIGHT_GREEN}{filled_url} redirects to {locations}{ENDC}')
            pbar.update()

async def process_urls(semaphore, session, urls, payloads, keyword):
    with tqdm(total=len(urls) * len(payloads), ncols=70, desc='Processing', unit='url', position=0) as pbar:
        tasks = []
        for url in urls:
            tasks.append(process_url(semaphore, session, url, payloads, keyword, pbar))
        await asyncio.gather(*tasks, return_exceptions=True)

async def main(args):
    payloads = await load_payloads(args.payloads)
    urls = load_urls()
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        await process_urls(semaphore, session, urls, payloads, args.keyword)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenRedirectValidator: A tool for detecting open redirect vulnerabilities")
    parser.add_argument('-p', '--payloads', help='file of payloads (default: payloads.txt)', required=False)
    parser.add_argument('-k', '--keyword', help='keyword in urls to replace with payload (default is FUZZ)', default="FUZZ")
    parser.add_argument('-c', '--concurrency', help='number of concurrent tasks (default is 100)', type=int, default=100)
    args = parser.parse_args()
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        sys.exit(0)
