import tkinter as tk

from tkinter import ttk, messagebox

import socket

import requests

import threading



                # GUI setup

app = tk.Tk()

app.title("All-in-One Pentester Toolkit - FuzzuTech")

app.geometry("600x500")

style = ttk.Style(app)

style.theme_use("clam")



                 # Header Label

header = ttk.Label(app, text="🔐 Pentester Toolkit GUI", font=("Helvetica", 18, "bold"), foreground="#1f6aa5")

header.pack(pady=10)





                            #  FUNCTIONS 

                           # Port Scanner

def scan_ports():

    output_text.delete(1.0, tk.END)

    host = port_host_entry.get()

    try:

        ip = socket.gethostbyname(host)

    except socket.gaierror:

        output_text.insert(tk.END, "Invalid host!\n")

        return



    for port in range(1, 100):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(0.5)

                result = s.connect_ex((ip, port))

                if result == 0:

                    output_text.insert(tk.END, f"Port {port} is open\n")

        except Exception:

            continue



                              # XSS Tester

def xss_test():

    output_text.delete(1.0, tk.END)

    url = xss_url_entry.get()

    payload = "<script>alert('XSS')</script>"

    try:

        response = requests.get(url + payload)

        if payload in response.text:

            output_text.insert(tk.END, "Vulnerable to XSS!\n")

        else:

            output_text.insert(tk.END, "No XSS detected.\n")

    except:

        output_text.insert(tk.END, "Error testing XSS.\n")



                                  # Brute Force (Dummy Local Login)

def brute_force_login():

    output_text.delete(1.0, tk.END)

    correct_username = "admin"

    correct_password = "1234"

    usernames = ["admin", "user"]

    passwords = ["123", "1234", "password"]



    for u in usernames:

        for p in passwords:

            if u == correct_username and p == correct_password:

                output_text.insert(tk.END, f"Success! Username: {u}, Password: {p}\n")

                return

            else:

                output_text.insert(tk.END, f"Tried {u}:{p} - Failed\n")



                                # GUI TABS 

tabs = ttk.Notebook(app)

tabs.pack(fill="both", expand=True)



# PORT SCANNER TAB

tab1 = ttk.Frame(tabs)

tabs.add(tab1, text="Port Scanner")

ttk.Label(tab1, text="Enter Host (e.g., google.com):").pack(pady=5)

port_host_entry = ttk.Entry(tab1, width=40)

port_host_entry.pack(pady=5)

ttk.Button(tab1, text="Scan Ports", command=lambda: threading.Thread(target=scan_ports).start()).pack(pady=10)



                                     # XSS TESTER TAB

tab2 = ttk.Frame(tabs)

tabs.add(tab2, text="XSS Tester")

ttk.Label(tab2, text="Enter URL (without payload):").pack(pady=5)

xss_url_entry = ttk.Entry(tab2, width=50)

xss_url_entry.pack(pady=5)

ttk.Button(tab2, text="Test XSS", command=xss_test).pack(pady=10)



                                     # Brute force

tab3 = ttk.Frame(tabs)

tabs.add(tab3, text="Brute Force")

ttk.Label(tab3, text="(Testing on Dummy Data)").pack(pady=5)

ttk.Button(tab3, text="Start Brute Force", command=brute_force_login).pack(pady=10)



                                   # Output text area for result

output_text = tk.Text(app, height=12, bg="#f0f0f0", font=("Courier", 10))

output_text.pack(padx=10, pady=10, fill="both", expand=True)



# To run the GUI 

app.mainloop()