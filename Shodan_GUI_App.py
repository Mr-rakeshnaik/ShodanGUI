#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Shodan GUI Security Tool
===============================================

This application provides an advanced graphical user interface (GUI) for the Shodan API,
designed for security professionals.

**Author:** Rakesh Naik M.
**Version:** 1.0.0
**License:** MIT
**LinkeIn:** https://www.linkedin.com/in/iamrakeshnaik/

"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import shodan
import threading
import queue
import json
import csv
import os
import urllib.request

class ShodanGUI:
    def __init__(self, master):
        self.master = master
        master.title("Shodan Security Tool - GUI Edition")
        master.geometry("1200x800")
        self.api_key_file = "shodan_api.key"
        self.current_thread = None
        self.abort_flag = threading.Event()

        # --- Main Layout ---
        top_frame = ttk.Frame(master, padding="10")
        top_frame.pack(fill="x")

        main_paned_window = ttk.PanedWindow(master, orient=tk.VERTICAL)
        main_paned_window.pack(fill="both", expand=True, padx=10, pady=5)

        notebook_frame = ttk.Frame(main_paned_window, padding="5")
        main_paned_window.add(notebook_frame, weight=1)

        output_container = ttk.LabelFrame(main_paned_window, text="Output Console", padding="5")
        main_paned_window.add(output_container, weight=2)

        # --- API Key Input ---
        ttk.Label(top_frame, text="Shodan API Key:").pack(side="left", padx=(0, 5))
        self.api_key_var = tk.StringVar()
        self.api_key_entry = ttk.Entry(top_frame, textvariable=self.api_key_var, width=50, show="*")
        self.api_key_entry.pack(side="left", fill="x", expand=True)
        self.load_api_key()

        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill="both", expand=True)

        self.create_search_tab()
        self.create_host_tab()
        self.create_internetdb_tab()
        self.create_domain_tab()
        self.create_vuln_tab()
        self.create_community_queries_tab()
        self.create_scan_tab()
        self.create_alert_tab()

        # --- Output & Controls ---
        self.output_text = scrolledtext.ScrolledText(output_container, wrap=tk.WORD, state="disabled", font=("Consolas", 10), bg="#2b2b2b", fg="#d3d3d3")
        self.output_text.pack(fill="both", expand=True, side="left")
        
        control_frame = ttk.Frame(output_container, padding="10")
        control_frame.pack(side="right", fill="y")
        self.abort_button = ttk.Button(control_frame, text="Abort Operation", command=self.abort_operation, state="disabled")
        self.abort_button.pack(pady=5)

        self.configure_text_colors()

        # --- Status Bar ---
        status_frame = ttk.Frame(master, padding="5")
        status_frame.pack(fill="x")
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(fill="x")

        # --- Threading Queue ---
        self.result_queue = queue.Queue()
        self.master.after(100, self.process_queue)
        
        self.last_results = {}
        self.last_query = ""

    def configure_text_colors(self):
        self.output_text.tag_configure("cyan", foreground="#00FFFF")
        self.output_text.tag_configure("green", foreground="#00FF00")
        self.output_text.tag_configure("red", foreground="#FF4500")
        self.output_text.tag_configure("yellow", foreground="#FFFF00")
        self.output_text.tag_configure("blue", foreground="#1E90FF")
        self.output_text.tag_configure("magenta", foreground="#FF00FF")
        self.output_text.tag_configure("white", foreground="#FFFFFF")

    def create_search_tab(self):
        self.search_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.search_tab, text="🔎 Advanced Search")

        form_frame = ttk.LabelFrame(self.search_tab, text="Search Filters", padding="10")
        form_frame.pack(fill="x")

        self.search_entries = {}
        filters = {
            "Keywords": "", "port": "", "country": "2-letter code", "city": "",
            "org": "ISP/Organization", "os": "Operating System", "hostname": "",
            "net": "CIDR format", "product": "", "version": ""
        }

        row = 0
        for filter_name, placeholder in filters.items():
            ttk.Label(form_frame, text=f"{filter_name.capitalize()}:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
            entry = ttk.Entry(form_frame, width=40)
            entry.grid(row=row, column=1, sticky="ew", padx=5, pady=5)
            if placeholder:
                entry.insert(0, placeholder)
                entry.config(foreground="grey")
                entry.bind("<FocusIn>", lambda e, p=placeholder: self.on_focus_in(e, p))
                entry.bind("<FocusOut>", lambda e, p=placeholder: self.on_focus_out(e, p))
            self.search_entries[filter_name.lower()] = entry
            row += 1

        checkbox_frame = ttk.Frame(form_frame)
        checkbox_frame.grid(row=row, column=0, columnspan=2, pady=10, sticky="w")
        self.has_vuln_var = tk.BooleanVar()
        self.has_screenshot_var = tk.BooleanVar()
        ttk.Checkbutton(checkbox_frame, text="Has Vulnerabilities", variable=self.has_vuln_var).pack(side="left", padx=5)
        ttk.Checkbutton(checkbox_frame, text="Has Screenshot", variable=self.has_screenshot_var).pack(side="left", padx=5)
        form_frame.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(self.search_tab)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Search Shodan", command=self.perform_advanced_search).pack(side="left")
        ttk.Button(button_frame, text="Get Stats (Facets)", command=self.perform_facet_search).pack(side="left", padx=10)
        ttk.Button(button_frame, text="Export Results", command=lambda: self.export_data("search")).pack(side="right")

    def on_focus_in(self, event, placeholder):
        if event.widget.get() == placeholder:
            event.widget.delete(0, "end")
            event.widget.config(foreground="black")

    def on_focus_out(self, event, placeholder):
        if not event.widget.get():
            event.widget.insert(0, placeholder)
            event.widget.config(foreground="grey")

    def build_search_query(self):
        query_parts = []
        for name, entry in self.search_entries.items():
            value = entry.get().strip()
            if value and value not in ["2-letter code", "ISP/Organization", "Operating System", "CIDR format"]:
                if name == "keywords":
                    query_parts.append(value)
                else:
                    query_parts.append(f"{name}:{value}")
        if self.has_vuln_var.get(): query_parts.append("has_vuln:true")
        if self.has_screenshot_var.get(): query_parts.append("has_screenshot:true")
        self.last_query = " ".join(query_parts)
        return self.last_query

    def perform_advanced_search(self):
        query = self.build_search_query()
        if not query:
            messagebox.showwarning("Input Required", "Please enter at least one search filter.")
            return
        self.run_in_thread(self.shodan_search, query)

    def perform_facet_search(self):
        query = self.last_query if self.last_query else self.build_search_query()
        if not query:
            messagebox.showwarning("Input Required", "Please perform a search or enter filters before getting stats.")
            return
        self.run_in_thread(self.shodan_facet_search, query)

    def create_host_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="💻 Host Lookup")
        
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill="x")
        ttk.Label(top_frame, text="IP Address:").pack(side="left", anchor="w")
        self.host_ip_entry = ttk.Entry(top_frame, width=40)
        self.host_ip_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(top_frame, text="Lookup Host", command=self.perform_host_lookup).pack(side="left")
        ttk.Button(top_frame, text="Get History", command=self.perform_host_history_lookup).pack(side="left", padx=5)
        
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Export Results", command=lambda: self.export_data("host")).pack(side="right")

    def perform_host_lookup(self):
        ip = self.host_ip_entry.get()
        if not ip: return messagebox.showwarning("Input Required", "Please enter an IP address.")
        self.run_in_thread(self.shodan_host, ip, False)

    def perform_host_history_lookup(self):
        ip = self.host_ip_entry.get()
        if not ip: return messagebox.showwarning("Input Required", "Please enter an IP address.")
        self.run_in_thread(self.shodan_host, ip, True)

    def create_internetdb_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="⚡ Quick Lookup (InternetDB)")
        
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill="x")
        ttk.Label(top_frame, text="IP Address:").pack(side="left", anchor="w")
        self.internetdb_ip_entry = ttk.Entry(top_frame, width=40)
        self.internetdb_ip_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(top_frame, text="Lookup", command=self.perform_internetdb_lookup).pack(side="left")

    def perform_internetdb_lookup(self):
        ip = self.internetdb_ip_entry.get()
        if not ip: return messagebox.showwarning("Input Required", "Please enter an IP address.")
        self.run_in_thread(self.shodan_internetdb, ip, is_public=True)

    def create_domain_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="🌐 Domain Info")
        
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill="x")
        ttk.Label(top_frame, text="Domain Name:").pack(side="left", anchor="w")
        self.domain_name_entry = ttk.Entry(top_frame, width=40)
        self.domain_name_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(top_frame, text="Get Domain Info", command=self.perform_domain_lookup).pack(side="left")
        
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Export Results", command=lambda: self.export_data("domain")).pack(side="right")

    def perform_domain_lookup(self):
        domain = self.domain_name_entry.get()
        if not domain: return messagebox.showwarning("Input Required", "Please enter a domain name.")
        self.run_in_thread(self.shodan_domain, domain)

    def create_vuln_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="💥 Vulnerabilities")

        form_frame = ttk.LabelFrame(tab, text="Vulnerability Filters", padding="10")
        form_frame.pack(fill="x")

        self.vuln_entries = {}
        filters = {
            "vuln": "CVE ID (e.g., CVE-2021-44228)",
            "product": "",
            "version": "",
            "os": ""
        }

        row = 0
        for filter_name, placeholder in filters.items():
            ttk.Label(form_frame, text=f"{filter_name.capitalize()}:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
            entry = ttk.Entry(form_frame, width=40)
            entry.grid(row=row, column=1, sticky="ew", padx=5, pady=5)
            if placeholder:
                entry.insert(0, placeholder)
                entry.config(foreground="grey")
                entry.bind("<FocusIn>", lambda e, p=placeholder: self.on_focus_in(e, p))
                entry.bind("<FocusOut>", lambda e, p=placeholder: self.on_focus_out(e, p))
            self.vuln_entries[filter_name] = entry
            row += 1
        
        form_frame.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(tab)
        button_frame.pack(fill="x", pady=10)
        ttk.Button(button_frame, text="Search Vulnerabilities", command=self.perform_vuln_search).pack(side="left")
        ttk.Button(button_frame, text="Export Results", command=lambda: self.export_data("vuln")).pack(side="right")

    def build_vuln_query(self):
        query_parts = ["has_vuln:true"]
        for name, entry in self.vuln_entries.items():
            value = entry.get().strip()
            if value and value not in ["CVE ID (e.g., CVE-2021-44228)"]:
                query_parts.append(f"{name}:{value}")
        return " ".join(query_parts)

    def perform_vuln_search(self):
        query = self.build_vuln_query()
        if not query: return messagebox.showwarning("Input Required", "Please enter at least one vulnerability filter.")
        self.run_in_thread(self.shodan_vuln_search, query)

    def create_community_queries_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="👥 Community Queries")
        
        ttk.Button(tab, text="Fetch Community Queries", command=lambda: self.run_in_thread(self.shodan_community_queries)).pack(pady=5, anchor="w")

        list_frame = ttk.Frame(tab)
        list_frame.pack(fill="both", expand=True, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.query_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.query_listbox.pack(side="left", fill="both", expand=True)
        self.query_listbox.bind("<<ListboxSelect>>", self.on_query_select)
        
        scrollbar.config(command=self.query_listbox.yview)

    def on_query_select(self, event):
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            query_text = event.widget.get(index)
            
            keywords_entry = self.search_entries.get("keywords")
            if keywords_entry:
                keywords_entry.config(foreground="black")
                keywords_entry.delete(0, tk.END)
                keywords_entry.insert(0, query_text)
            
            self.notebook.select(self.search_tab)
            messagebox.showinfo("Query Selected", f"'{query_text}' has been copied to the Advanced Search tab.")

    def create_scan_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="📡 On-Demand Scan")
        ttk.Label(tab, text="IP or Network (CIDR):").pack(anchor="w")
        self.scan_target_entry = ttk.Entry(tab, width=40)
        self.scan_target_entry.pack(fill="x", pady=5)
        ttk.Button(tab, text="Initiate Scan", command=self.perform_scan).pack(pady=10)

    def perform_scan(self):
        target = self.scan_target_entry.get()
        if not target: return messagebox.showwarning("Input Required", "Please enter a target IP or network.")
        self.run_in_thread(self.shodan_scan, target)

    def create_alert_tab(self):
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="🚨 Alerts")
        ttk.Button(tab, text="List My Alerts", command=lambda: self.run_in_thread(self.shodan_list_alerts)).pack(pady=5, anchor="w")
        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(tab, text="Create New Alert").pack(anchor="w")
        ttk.Label(tab, text="Alert Name:").pack(anchor="w", pady=(5,0))
        self.alert_name_entry = ttk.Entry(tab, width=40)
        self.alert_name_entry.pack(fill="x", pady=5)
        ttk.Label(tab, text="IP or CIDR to Monitor:").pack(anchor="w")
        self.alert_ip_entry = ttk.Entry(tab, width=40)
        self.alert_ip_entry.pack(fill="x", pady=5)
        ttk.Button(tab, text="Create Alert", command=self.perform_create_alert).pack(pady=5, anchor="w")
        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=10)
        ttk.Label(tab, text="Delete Alert").pack(anchor="w")
        ttk.Label(tab, text="Alert ID:").pack(anchor="w", pady=(5,0))
        self.alert_id_entry = ttk.Entry(tab, width=40)
        self.alert_id_entry.pack(fill="x", pady=5)
        ttk.Button(tab, text="Delete Alert", command=self.perform_delete_alert).pack(pady=5, anchor="w")

    def perform_create_alert(self):
        name = self.alert_name_entry.get()
        ip = self.alert_ip_entry.get()
        if not name or not ip: return messagebox.showwarning("Input Required", "Please provide both a name and an IP/CIDR.")
        self.run_in_thread(self.shodan_create_alert, name, ip)

    def perform_delete_alert(self):
        alert_id = self.alert_id_entry.get()
        if not alert_id: return messagebox.showwarning("Input Required", "Please provide an Alert ID to delete.")
        self.run_in_thread(self.shodan_delete_alert, alert_id)

    def get_api(self):
        api_key = self.api_key_var.get()
        if not api_key:
            messagebox.showerror("Error", "Please enter your Shodan API key.")
            return None
        self.save_api_key(api_key)
        return shodan.Shodan(api_key)

    def save_api_key(self, api_key):
        try:
            with open(self.api_key_file, "w") as f: f.write(api_key)
        except IOError: pass

    def load_api_key(self):
        if os.path.exists(self.api_key_file):
            try:
                with open(self.api_key_file, "r") as f: self.api_key_var.set(f.read().strip())
            except IOError: pass

    def write_output(self, text, tag=None):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, text + "\n", tag)
        self.output_text.config(state="disabled")
        self.output_text.see(tk.END)

    def run_in_thread(self, target_func, *args, is_public=False):
        api = None
        if not is_public:
            api = self.get_api()
            if not api: return
        
        self.abort_flag.clear()
        self.abort_button.config(state="normal")
        
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")
        
        thread_args = (api, *args) if not is_public else args
        self.current_thread = threading.Thread(target=target_func, args=thread_args, daemon=True)
        self.current_thread.start()

    def abort_operation(self):
        if self.current_thread and self.current_thread.is_alive():
            self.abort_flag.set()
            self.set_status("Aborting operation...")

    def process_queue(self):
        try:
            message = self.result_queue.get_nowait()
            if "status" in message: self.status_var.set(message["status"])
            if "output" in message: self.write_output(message["output"], message.get("tag"))
            if "output_chunk" in message:
                self.output_text.config(state="normal")
                for text, tag in message["output_chunk"]:
                    self.output_text.insert(tk.END, text + "\n", tag)
                self.output_text.config(state="disabled")
                self.output_text.see(tk.END)
            if "done" in message and message["done"]:
                self.abort_button.config(state="disabled")
                self.abort_flag.clear()
            if "populate_queries" in message:
                self.query_listbox.delete(0, tk.END)
                for query in message["populate_queries"]:
                    self.query_listbox.insert(tk.END, query)
        except queue.Empty: pass
        finally: self.master.after(100, self.process_queue)

    def post_message(self, text, tag=None): self.result_queue.put({"output": text, "tag": tag})
    def set_status(self, text): self.result_queue.put({"status": text})
    def signal_done(self): self.result_queue.put({"done": True})
    def populate_queries(self, queries): self.result_queue.put({"populate_queries": queries})
    def post_buffered_chunk(self, chunk): self.result_queue.put({"output_chunk": chunk})

    # --- Shodan API Functions ---
    def shodan_search(self, api, query):
        self.set_status(f"Searching for: '{query}'...")
        self.post_message(f"[*] Searching Shodan for: '{query}'", "cyan")
        try:
            results = api.search(query)
            self.last_results["search"] = results['matches']
            self.post_message(f"[*] Results found: {results['total']}", "green")
            
            output_buffer = []
            for i, result in enumerate(self.last_results["search"]):
                if self.abort_flag.is_set(): break
                output_buffer.append(("-" * 100, "blue"))
                output_buffer.append((f"IP: {result['ip_str']} Port: {result['port']} Org: {result.get('org', 'N/A')}", "white"))
                output_buffer.append((f"Hostnames: {', '.join(result['hostnames'])}", "white"))
                output_buffer.append(("Banner:", "yellow"))
                output_buffer.append((result['data'], "white"))
                
                if (i + 1) % 10 == 0:
                    self.post_buffered_chunk(output_buffer)
                    output_buffer = []
            
            if output_buffer:
                self.post_buffered_chunk(output_buffer)

        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready" if not self.abort_flag.is_set() else "Operation Aborted"); self.signal_done()

    def shodan_facet_search(self, api, query):
        self.set_status(f"Getting stats for: '{query}'...")
        self.post_message(f"[*] Getting stats for: '{query}'", "cyan")
        try:
            facets = [('org', 10), ('country', 10), ('product', 10), ('port', 10)]
            results = api.count(query, facets=facets)
            self.post_message(f"[*] Total Results: {results['total']}", "green")
            for facet_name, data in results['facets'].items():
                self.post_message(f"\n--- Top {len(data)} {facet_name.capitalize()} ---", "yellow")
                for item in data:
                    self.post_message(f"  {item['value']}: {item['count']:,}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_host(self, api, ip, history=False):
        self.set_status(f"Looking up host: {ip}...")
        self.post_message(f"[*] Looking up host: {ip} (History: {history})", "cyan")
        try:
            host = api.host(ip, history=history)
            self.last_results["host"] = [host]
            if history:
                self.post_message(f"[*] Found {len(host['data'])} historical banners for {ip}", "green")
                output_buffer = []
                for i, banner in enumerate(host['data']):
                    output_buffer.append(("-" * 100, "blue"))
                    output_buffer.append((f"Port: {banner['port']}  Timestamp: {banner['timestamp']}", "white"))
                    output_buffer.append(("Banner:", "yellow"))
                    output_buffer.append((banner['data'], "white"))
                    if (i + 1) % 10 == 0:
                        self.post_buffered_chunk(output_buffer)
                        output_buffer = []
                if output_buffer:
                    self.post_buffered_chunk(output_buffer)
            else:
                self.post_message("General Information:", "green")
                self.post_message(f"  IP: {host['ip_str']}  Country: {host.get('country_name', 'N/A')}", "white")
                self.post_message(f"  Organization: {host.get('org', 'N/A')}  OS: {host.get('os', 'N/A')}", "white")
                self.post_message("Ports:", "green")
                for port in host.get('ports', []): self.post_message(f"  - {port}", "white")
                self.post_message("Vulnerabilities:", "red")
                for vuln in host.get('vulns', []): self.post_message(f"  - {vuln}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_internetdb(self, ip):
        self.set_status(f"Querying InternetDB for {ip}...")
        self.post_message(f"[*] Querying InternetDB for: {ip}", "cyan")
        try:
            req = urllib.request.Request(
                f"https://internetdb.shodan.io/{ip}", 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
            self.post_message("Open Ports:", "green")
            self.post_message(f"  {', '.join(map(str, data.get('ports', [])))}", "white")
            self.post_message("Hostnames:", "green")
            self.post_message(f"  {', '.join(data.get('hostnames', []))}", "white")
            self.post_message("CPEs:", "green")
            self.post_message(f"  {', '.join(data.get('cpes', []))}", "white")
            self.post_message("Vulnerabilities:", "red")
            self.post_message(f"  {', '.join(data.get('vulns', []))}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_domain(self, api, domain):
        self.set_status(f"Fetching info for domain: {domain}...")
        self.post_message(f"[*] Fetching info for domain: {domain}", "cyan")
        try:
            domain_info = api.dns.domain_info(domain)
            self.last_results["domain"] = [domain_info]
            self.post_message("Subdomains:", "green")
            for sub in domain_info.get('subdomains', []): self.post_message(f" - {sub}.{domain}", "white")
            self.post_message("\nDNS Records:", "green")
            for record in domain_info.get('data', []):
                self.post_message(f" - Type: {record['type']}, Value: {record['value']}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_vuln_search(self, api, query):
        self.set_status(f"Searching for vulnerable devices: '{query}'...")
        self.post_message(f"[*] Searching for: '{query}'", "cyan")
        try:
            results = api.search(query)
            self.last_results["vuln"] = results['matches']
            self.post_message(f"[*] Results found: {results['total']}", "green")
            output_buffer = []
            for i, result in enumerate(self.last_results["vuln"]):
                if self.abort_flag.is_set(): break
                output_buffer.append(("-" * 100, "blue"))
                output_buffer.append((f"IP: {result['ip_str']} Port: {result['port']} Org: {result.get('org', 'N/A')}", "white"))
                if result.get('vulns'):
                    output_buffer.append(("Vulnerabilities:", "red"))
                    for cve, _ in result['vulns'].items(): output_buffer.append((f"  - {cve}", "white"))
                output_buffer.append(("Banner:", "yellow"))
                output_buffer.append((result['data'], "white"))

                if (i + 1) % 10 == 0:
                    self.post_buffered_chunk(output_buffer)
                    output_buffer = []
            
            if output_buffer:
                self.post_buffered_chunk(output_buffer)

        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready" if not self.abort_flag.is_set() else "Operation Aborted"); self.signal_done()

    def shodan_community_queries(self, api):
        self.set_status("Fetching community queries...")
        self.post_message("[*] Fetching community queries...", "cyan")
        try:
            results = api.queries()
            self.last_results["community_queries"] = [{"query": q} for q in results]
            self.populate_queries(results)
            self.post_message(f"[*] Found {len(results)} queries. Click on a query in the list to use it.", "green")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def export_data(self, data_key):
        if not self.last_results.get(data_key):
            return messagebox.showinfo("No Data", f"No data available to export for '{data_key}'. Please perform a search first.")
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        if not file_path: return

        data_to_export = self.last_results[data_key]
        
        try:
            if file_path.endswith(".json"):
                with open(file_path, 'w') as f:
                    json.dump(data_to_export, f, indent=4)
            elif file_path.endswith(".csv"):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if not data_to_export: return
                    headers = set()
                    for item in data_to_export:
                        headers.update(item.keys())
                    writer = csv.DictWriter(f, fieldnames=sorted(list(headers)))
                    writer.writeheader()
                    writer.writerows(data_to_export)
            messagebox.showinfo("Success", f"Successfully exported {len(data_to_export)} results to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")

    def shodan_scan(self, api, target):
        self.set_status(f"Initiating scan for {target}...")
        self.post_message(f"[*] Initiating scan for: {target}", "cyan")
        try:
            scan = api.scan(target)
            self.post_message("Scan submitted successfully!", "green")
            self.post_message(f"  Scan ID: {scan['id']}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_list_alerts(self, api):
        self.set_status("Fetching alerts...")
        self.post_message("[*] Fetching network alerts...", "cyan")
        try:
            alerts = api.alerts()
            if not alerts: return self.post_message("No alerts found.", "yellow")
            for alert in alerts:
                self.post_message("-" * 50, "blue")
                self.post_message(f"ID: {alert['id']}", "white")
                self.post_message(f"Name: {alert['name']}", "white")
                self.post_message(f"IPs: {', '.join(alert['filters']['ip'])}", "white")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_create_alert(self, api, name, ip):
        self.set_status(f"Creating alert '{name}'...")
        try:
            api.create_alert(name, ip)
            self.post_message(f"Alert '{name}' created successfully!", "green")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()

    def shodan_delete_alert(self, api, alert_id):
        self.set_status(f"Deleting alert ID {alert_id}...")
        try:
            api.delete_alert(alert_id)
            self.post_message(f"Alert '{alert_id}' deleted successfully.", "green")
        except Exception as e: self.post_message(f"API Error: {e}", "red")
        finally: self.set_status("Ready"); self.signal_done()
            
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
        style.configure("TNotebook.Tab", padding=[10, 5], font=('Helvetica', 10))
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
    app = ShodanGUI(root)
    root.mainloop()
