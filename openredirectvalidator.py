#!/usr/bin/env python3
import asyncio
import aiohttp
from aiohttp import ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List
import tkinter as tk
from tkinter import ttk, Menu, font
import threading
import itertools
import time
import socket

# Color Scheme
DARK_BG = "#1C2526"         # Deep dark gray background
MEDIUM_GRAY = "#2E2E2E"     # Widget background
LIGHT_TEXT = "#E0E0E0"      # Light gray text
GOLD_ACCENT = "#D4A017"     # Muted gold for accents
GOLD_HOVER = "#D4A017"      # Brighter gold for hover/selection
BLACK_BORDER = "#000000"    # Black border color

async def load_payloads():
    try:
        with open("payloads.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]  # Skip empty lines
    except FileNotFoundError:
        raise Exception("payloads.txt not found. Please create the file with payloads.")

def fuzzify_url(url: str, keyword: str) -> str:
    if keyword in url:
        return url
    parsed_url = urlparse(url)
    params = parse_qsl(parsed_url.query)
    fuzzed_params = [(k, keyword) for k, _ in params]
    fuzzed_query = urlencode(fuzzed_params)
    return urlunparse(
        [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment])

async def fetch_url(session, url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc or parsed.netloc == "\\":
        return None
    try:
        async with session.head(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as response:
            return response
    except (ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects, UnicodeDecodeError, socket.gaierror, asyncio.exceptions.TimeoutError):
        return None

async def process_url(semaphore, session, url, payloads, keyword, output_tree, sn_counter, progress_bar, progress_label, total_tasks, start_time, root):
    async with semaphore:
        original_domain = urlparse(url).netloc
        processed = 0
        redirects_found = 0  # Track if any redirects are found
        for payload in payloads:
            filled_url = url.replace(keyword, payload)
            response = await fetch_url(session, filled_url)
            processed += 1
            elapsed = time.time() - start_time
            percent = (processed / total_tasks) * 100
            remaining = (elapsed / processed) * (total_tasks - processed) if processed > 0 else 0

            def update_progress():
                progress_bar["value"] = processed
                progress_label.config(text=f"Processing: {percent:.0f}% | {processed}/{total_tasks} [{elapsed:.0f}s<{remaining:.0f}s]")
                root.update_idletasks()

            root.after(0, update_progress)

            if response and response.history:
                final_url = str(response.url)
                final_domain = urlparse(final_url).netloc
                if final_domain and final_domain != original_domain:
                    redirects_found += 1
                    sn = next(sn_counter)
                    max_width = 400 // 8
                    underline = '_' * min(len(filled_url), max_width)
                    underlined_url = f"{filled_url} {underline}"

                    def add_result():
                        output_tree.insert('', tk.END, values=(sn, underlined_url, final_url))
                        root.update_idletasks()

                    root.after(0, add_result)

        # After processing all payloads, check if no redirects were found
        if processed == total_tasks and redirects_found == 0:
            def no_redirects_message():
                output_tree.insert('', tk.END, values=("", "No open redirects found", ""))
                # Center the message in "VULNERABLE ENDPOINT" column
                output_tree.item(output_tree.get_children()[-1], option='values', values=("", "No open redirects found", ""))
                root.update_idletasks()
            root.after(0, no_redirects_message)

async def process_urls(urls, payloads, keyword, concurrency, output_tree, progress_bar, progress_label, sn_counter, root):
    global start_time
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = []
        total_tasks = len(urls) * len(payloads)
        progress_bar["maximum"] = total_tasks
        for url in urls:
            task = process_url(semaphore, session, url, payloads, keyword, output_tree, sn_counter, progress_bar, progress_label, total_tasks, start_time, root)
            tasks.append(task)

        await asyncio.gather(*tasks)

def run_scan(url_entry, output_tree, progress_bar, progress_label, payloads_file="payloads.txt", keyword="FUZZ", concurrency=100, root=None):
    urls = [url_entry.get().strip()]
    if not urls[0]:
        output_tree.insert('', tk.END, values=("", "Please enter a URL.", ""))
        return

    for item in output_tree.get_children():
        output_tree.delete(item)
    progress_bar["value"] = 0
    progress_label.config(text="Processing: 0% | 0/0 [0s<0s]")

    sn_counter = itertools.count(1)

    async def async_run():
        try:
            payloads = await load_payloads()
            await process_urls(urls, payloads, keyword, concurrency, output_tree, progress_bar, progress_label, sn_counter, root)
        except Exception as e:
            def show_error():
                output_tree.insert('', tk.END, values=("", str(e), ""))
                root.update_idletasks()
            root.after(0, show_error)

    threading.Thread(target=lambda: asyncio.run(async_run()), daemon=True).start()

def create_context_menu(event, output_tree, root):
    item = output_tree.identify_row(event.y)
    if item:
        output_tree.selection_set(item)
        selected_item = output_tree.selection()
        if selected_item:
            item_values = output_tree.item(selected_item, 'values')
            if item_values and len(item_values) >= 2:
                vulnerable_url = item_values[1].split(' ')[0]
                menu = Menu(root, tearoff=0, bg=MEDIUM_GRAY, fg=LIGHT_TEXT, activebackground=GOLD_HOVER, activeforeground=LIGHT_TEXT)
                menu.add_command(label="Copy URL", command=lambda: root.clipboard_append(vulnerable_url))
                menu.post(event.x_root, event.y_root)

def create_gui():
    global root, urls, start_time
    urls = []
    root = tk.Tk()
    root.title("OpenRedirectValidator - Open Redirect Scanner")
    root.geometry("900x600")
    root.configure(bg=DARK_BG)

    style = ttk.Style()
    style.theme_use('default')
    style.configure("TProgressbar", background=GOLD_ACCENT, troughcolor=DARK_BG, bordercolor=MEDIUM_GRAY)
    style.configure("Treeview", background=MEDIUM_GRAY, foreground=LIGHT_TEXT, fieldbackground=MEDIUM_GRAY, rowheight=25)
    style.configure("Treeview.Heading", background=MEDIUM_GRAY, foreground=LIGHT_TEXT, borderwidth=1, relief="flat")
    style.map("Treeview.Heading", background=[('active', MEDIUM_GRAY)], foreground=[('active', LIGHT_TEXT)])
    style.map("Treeview", background=[('selected', GOLD_HOVER)], foreground=[('selected', LIGHT_TEXT)])
    style.configure("TFrame", background=DARK_BG)

    url_frame = ttk.Frame(root)
    url_frame.pack(pady=5, fill=tk.X)

    tk.Label(url_frame, text="Enter URL:", bg=DARK_BG, fg=LIGHT_TEXT).pack(side=tk.LEFT, padx=5)

    entry_border_frame = tk.Frame(url_frame, bg=BLACK_BORDER, bd=1)
    entry_border_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1, pady=1)
    url_entry = tk.Entry(entry_border_frame, width=60, bg=MEDIUM_GRAY, fg=LIGHT_TEXT, insertbackground=LIGHT_TEXT, borderwidth=0, highlightthickness=0)
    url_entry.pack(fill=tk.X, expand=True, padx=1, pady=1)
    url_entry.insert(0, "")

    scan_border_frame = tk.Frame(url_frame, bg=BLACK_BORDER, bd=1)
    scan_border_frame.pack(side=tk.LEFT, padx=5, pady=1)
    scan_button = tk.Button(scan_border_frame, text="Start Scan", command=lambda: run_scan(url_entry, output_tree, progress_bar, progress_label, root=root), bg=MEDIUM_GRAY, fg=LIGHT_TEXT, activebackground=GOLD_ACCENT, activeforeground=LIGHT_TEXT, borderwidth=0, highlightthickness=0)
    scan_button.pack(padx=1, pady=1)

    quit_border_frame = tk.Frame(url_frame, bg=BLACK_BORDER, bd=1)
    quit_border_frame.pack(side=tk.LEFT, padx=5, pady=1)
    quit_button = tk.Button(quit_border_frame, text="Quit", command=root.quit, bg=MEDIUM_GRAY, fg=LIGHT_TEXT, activebackground=GOLD_ACCENT, activeforeground=LIGHT_TEXT, borderwidth=0, highlightthickness=0)
    quit_button.pack(padx=1, pady=1)

    progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="TProgressbar")
    progress_bar.pack(pady=5)

    progress_label = tk.Label(root, text="Processing: 0% | 0/0 [0s<0s]", font=("Courier", 10), bg=DARK_BG, fg=LIGHT_TEXT)
    progress_label.pack(pady=5)

    output_frame = ttk.Frame(root)
    output_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    
    output_tree = ttk.Treeview(output_frame, columns=("SN", "VULNERABLE ENDPOINT", "REDIRECTED TO"), show="headings", height=20)
    output_tree.heading("SN", text="SN")
    output_tree.heading("VULNERABLE ENDPOINT", text="VULNERABLE ENDPOINT")
    output_tree.heading("REDIRECTED TO", text="REDIRECTED TO")
    output_tree.column("SN", width=50, anchor=tk.CENTER)
    output_tree.column("VULNERABLE ENDPOINT", width=400, anchor=tk.CENTER)  # Center-align this column
    output_tree.column("REDIRECTED TO", width=400, anchor=tk.CENTER)
    
    output_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    output_tree.bind("<Button-3>", lambda event: create_context_menu(event, output_tree, root))

    root.mainloop()

if __name__ == "__main__":
    create_gui()
