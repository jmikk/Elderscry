import json
import os
import re
import time
import threading
import requests
import sseclient
from datetime import datetime
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, colorchooser, scrolledtext
import xml.etree.ElementTree as ET


CONFIG_FILE = "config.json"
LOG_FILE = "event_log.txt"

COMMON_FILTERS = {
    "Issues Answered (Legislation)": r"\bnew legislation\b",
    "RMB Posts": r"\bregional message board\b",
    "Embassy Activity": r"\bembassy\b",
    "Ejections": r"\bejected\b",
    "Ceased to Exist": r"\bcease to exist\b",
    "Delegate Votes/Resolutions": r"\bresolution\b",
    "Moves": r"\brelocated from\b",
    "Influence": r"\binfluence in\b",
    "Changed Flags": r"\baltered its national flag\b",
    "Region Update": r"\b@@ updated\.\b",
    "Foundings": r"\bwas founded in\b",
    "Reclassified": r"\bwas reclassified from\b",
    "National Fields": r"\bchanged its national\b",
    "Agreed to Embassy": r"\bagreed to construct embassies between\b",
    "Closing Embassy": r"\bordered the closure of embassies between\b",
    "Proposed Embassy": r"\bproposed constructing embassies between\b",
    "Cancelled closure of Embassies": r"\b cancelled the closure of embassies between\b",
    "Rejected Embassy": r"\brejected a request from\b",
    "Aborted construction of embassies": r"\baborted construction of embassies between\b",
    "Embassy closed": r"\bEmbassy cancelled between\b",
    "Embassy established": r"\bEmbassy established between\b",
    "Banjects": r"\bwas ejected and banned from\b",
    "Ejections": r"\bwas ejected from\b",
    "Baning": r"\bbanned .*? from the region\b",
    "Unbanning": r"\bremoved .*? from the regional ban list\b",
    "RO Rename": r"\brenamed the office held\b",
    "RO power change": r"\bgranted (.+?) authority to .*? as .*?\b",
    "World Factbook Update": r"\bupdated the World Factbook entry\b",
    "Changed Regional Banner": r"\bchanged the regional banner\b",
    "Resigned from Office": r"\bresigned as .*? of\b",
    "Renamed Office": r'\brenamed the .*? from ".*?" to .*? in\b',
    "Changed Regional Flag": r"\baltered the regional flag\b",
    "Appointed to Office": r"\bappointed .*? as .*? with authority over .*? in\b",
    "Region Passworded": r"\bpassword-protected\b",
    "Tag Added": r'\badded the tag ".*?" to\b',
    "Tag removed": r'\bremoved the tag ".*?" to\b',
    "Revoked Powers": r"\bremoved .*? authority from .*? in\b",
    "Welcome Telegram Created": r"\bcomposed a new Welcome Telegram\b",
    "Region Founded": r"\bfounded the region\b",
    "Governor's Office Named": r"\bnamed the Governor\'s office\b",
    "Dismissed from Office": r"\bdismissed .*? as .*? of\b",
    "Map Created": r"\bcreated a map\b",
    "Map Version Created": r"\bcreated a map version\b",
    "Map Updated": r"\bupdated a map to a map version\b",
    "Map Endorsed": r"\bendorsed a map\b",
    "Map Endorsement Removed": r"\bremoved its endorsement from a map\b",
    "Poll Created": r"\bcreated a new poll in\b",
    "WA Vote Cast": r"\bvoted (for|against) the World Assembly Resolution\b",
    "Census Rank Achieved": r"\bwas ranked in the Top \d+% of the world for\b",
    "WA Proposal Approved": r"\bapproved the World Assembly proposal\b",
    "Endorsement Given": r"\bendorsed @@.*?@@",
    "WA Applied": r"\bapplied to join the World Assembly\b",
    "WA Admitted": r"\bwas admitted to the World Assembly\b",
    "WA Resigned": r"\bresigned from the World Assembly\b",
    "Delegate Changed": r"\bbecame WA Delegate of\b",
    "Delegate Seized": r"\bseized the position of .*? WA Delegate from\b",
    "Delegate Lost": r"\blost WA Delegate status in\b",
    "Endorsement Withdrawn": r"\bwithdrew (?:its|their|his|her) endorsement from\b",
    "Refoundings": r"\bwas refounded in\b",
    "Custom Banner Created": r"\bcreated a custom banner\b",
    "Region Password Removed": r"\bremoved regional password protection from\b",
}


class Elderscry:
    def __init__(self, root):
        self.root = root
        self.root.title("NationStates SSE Bot")

        self.listener_thread = None
        self.stop_event = threading.Event()

        self.config = self.load_config()
        self.create_widgets()

        if self.validate_webhook(self.config["webhook"]):
            self.log("Webhook validated.")
        else:
            self.log("WARNING: Webhook invalid!")

    def hyperlink(self, text):
        # Hyperlink nations
        text = re.sub(
            r"@@(.*?)@@",
            lambda m: f"[{m.group(1)}](https://www.nationstates.net/nation={m.group(1).lower().replace(' ', '_')})",
            text,
        )
        # Hyperlink regions
        text = re.sub(
            r"%%(.*?)%%",
            lambda m: f"[{m.group(1)}](https://www.nationstates.net/region={m.group(1).lower().replace(' ', '_')})",
            text,
        )
        return text

    def create_widgets(self):
        self.tabControl = ttk.Notebook(self.root)

        self.tab_feed = ttk.Frame(self.tabControl)
        self.tab_config = ttk.Frame(self.tabControl)
        self.tab_log = ttk.Frame(self.tabControl)

        self.tabControl.add(self.tab_feed, text="Live Feed")
        self.tabControl.add(self.tab_config, text="Config Editor")
        self.tabControl.add(self.tab_log, text="Log Viewer")

        self.tabControl.pack(expand=1, fill="both")
        self.create_feed_tab()
        self.create_config_tab()
        self.create_log_tab()

    def create_feed_tab(self):
        self.feed_text = scrolledtext.ScrolledText(
            self.tab_feed, state="disabled", wrap="word"
        )
        self.feed_text.pack(fill="both", expand=True)

        self.start_btn = ttk.Button(
            self.tab_feed, text="Start Listener", command=self.start_listener
        )
        self.start_btn.pack(side="left")

        self.stop_btn = ttk.Button(
            self.tab_feed, text="Stop Listener", command=self.stop_listener
        )
        self.stop_btn.pack(side="right")

    def create_config_tab(self):
        notebook = ttk.Notebook(self.tab_config)
        notebook.pack(expand=1, fill="both")

        # Save button below the tabs
        save_frame = ttk.Frame(self.tab_config)
        save_frame.pack(fill="x", pady=5)
        ttk.Button(save_frame, text="Save Config", command=self.save_config).pack(
            side="right", padx=10
        )

        # Define subtabs
        tabs = {
            "Info": ttk.Frame(notebook),
            "General": ttk.Frame(notebook),
            "Embassies": ttk.Frame(notebook),
            "Regional Changes": ttk.Frame(notebook),
            "RO Actions": ttk.Frame(notebook),
            "Nation Changes": ttk.Frame(notebook),
            "Maps": ttk.Frame(notebook),
            "WA & Polls": ttk.Frame(notebook),
            "Miscellaneous": ttk.Frame(notebook),
        }

        for name, tab in tabs.items():
            notebook.add(tab, text=name)

        # Info Tab
        info_frame = tabs["Info"]
        ttk.Label(info_frame, text="Region:").grid(row=0, column=0)
        region = self.config["region"].lower().replace(" ", "_")
        self.region_var = tk.StringVar(value=region)
        ttk.Entry(info_frame, textvariable=self.region_var).grid(row=0, column=1)

        ttk.Label(info_frame, text="Webhook:").grid(row=1, column=0)
        self.webhook_var = tk.StringVar(value=self.config["webhook"])
        ttk.Entry(info_frame, textvariable=self.webhook_var, width=60).grid(
            row=1, column=1
        )

        ttk.Label(info_frame, text="User Agent:").grid(row=2, column=0)
        self.user_agent_var = tk.StringVar(value="9005")
        ttk.Entry(info_frame, textvariable=self.user_agent_var).grid(row=2, column=1)

        self.dispatch_var = tk.BooleanVar(value=self.config["dispatch"]["enabled"])
        ttk.Checkbutton(
            info_frame, text="Enable Dispatch", variable=self.dispatch_var
        ).grid(row=3, column=0)

        self.dispatch_color = self.config["dispatch"]["color"]
        self.dispatch_role = tk.StringVar(
            value=self.config["dispatch"].get("role_id") or ""
        )

        ttk.Button(
            info_frame, text="Dispatch Color", command=self.pick_dispatch_color
        ).grid(row=3, column=1)
        ttk.Entry(info_frame, textvariable=self.dispatch_role).grid(row=3, column=2)
        ttk.Label(info_frame, text="Role ID").grid(row=3, column=3)

        # Create filter checkboxes grouped into subtabs
        self.common_filter_vars = {}
        self.common_filter_colors = {}
        self.common_filter_messages = {}

        row_dict = {tab: 3 for tab in tabs.values()}

        for name, pattern in COMMON_FILTERS.items():
            # Determine which subtab this filter belongs to
            if name in [
                "Issues Answered (Legislation)",
                "RMB Posts",
                "Ceased to Exist",
                "Influence",
                "Moves",
            ]:
                parent = tabs["General"]
            elif "Embassy" in name:
                parent = tabs["Embassies"]
            elif name in [
                "Changed Flags",
                "Changed Regional Banner",
                "Changed Regional Flag",
                "Region Passworded",
                "Region Password Removed" "Region Founded",
            ]:
                parent = tabs["Regional Changes"]
            elif name in [
                "RO Rename",
                "RO power change",
                "Appointed to Office",
                "Resigned from Office",
                "Renamed Office",
                "Revoked Powers",
                "Dismissed from Office",
                "Governor's Office Named",
            ]:
                parent = tabs["RO Actions"]
            elif name in [
                "Reclassified",
                "National Fields",
                "Tag Added",
                "Tag Removed",
                "Banjects",
                "Ejections",
                "Baning (Not currently supported)",
                "Unbanning (Not currently supported)",
            ]:
                parent = tabs["Nation Changes"]
            elif name.startswith("Map"):
                parent = tabs["Maps"]
            elif name in [
                "Poll Created",
                "WA Vote Cast",
                "Census Rank Achieved",
                "WA Proposal Approved",
                "Endorsement Given",
                "Endorsement Withdrawn",
                "WA Applied",
                "WA Admitted",
                "WA Resigned",
                "Delegate Changed",
                "Delegate Seized",
                "Delegate Lost",
            ]:
                parent = tabs["WA & Polls"]
            else:
                parent = tabs["Miscellaneous"]

            var = tk.BooleanVar(
                value=any(f["pattern"] == pattern for f in self.config["filters"])
            )
            ttk.Checkbutton(parent, text=name, variable=var).grid(
                row=row_dict[parent], column=0, sticky="w"
            )
            self.common_filter_vars[pattern] = var

            saved_color = next(
                (f["color"] for f in self.config["filters"] if f["pattern"] == pattern),
                3447003,
            )
            color_var = tk.IntVar(value=saved_color)

            def make_color_picker(pattern=pattern, var=color_var):
                def picker():
                    color = colorchooser.askcolor(title="Pick color")[1]
                    if color:
                        var.set(int(color.lstrip("#"), 16))

                return picker

            ttk.Button(parent, text="Pick Color", command=make_color_picker()).grid(
                row=row_dict[parent], column=1
            )
            self.common_filter_colors[pattern] = color_var

            saved_role = next(
                (
                    f["role_id"]
                    for f in self.config["filters"]
                    if f["pattern"] == pattern and f["role_id"]
                ),
                "",
            )
            msg_var = tk.StringVar(value=saved_role)

            ttk.Entry(parent, textvariable=msg_var, width=30).grid(
                row=row_dict[parent], column=2
            )
            self.common_filter_messages[pattern] = msg_var

            row_dict[parent] += 1

        # Custom filters list
        custom_frame = ttk.Frame(tabs["Miscellaneous"])
        custom_frame.grid(
            row=row_dict[tabs["Miscellaneous"]], column=0, columnspan=4, pady=10
        )

        ttk.Label(custom_frame, text="Custom Regex Filters:").grid(row=0, column=0)
        self.filters_listbox = tk.Listbox(custom_frame, width=80)
        self.filters_listbox.grid(row=1, column=0, columnspan=4)
        self.update_filters_listbox()

        ttk.Button(
            custom_frame, text="Add Custom Filter", command=self.add_filter
        ).grid(row=2, column=0)
        ttk.Button(
            custom_frame, text="Remove Selected", command=self.remove_filter
        ).grid(row=2, column=1)
        ttk.Button(custom_frame, text="Save Config", command=self.save_config).grid(
            row=3, column=0
        )

    def create_log_tab(self):
        self.log_text = scrolledtext.ScrolledText(
            self.tab_log, state="normal", wrap="word"
        )
        self.log_text.pack(fill="both", expand=True)
        self.refresh_log()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                return json.load(f)
        else:
            default = {
                "region": "testregion",
                "webhook": "",
                "dispatch": {"enabled": True, "color": 7506394, "role_id": None},
                "filters": [],
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(default, f, indent=4)
            return default

    def save_config(self):
        self.config["region"] = self.region_var.get().strip().lower().replace(" ", "_")
        self.config["webhook"] = self.webhook_var.get().strip()
        self.config["dispatch"]["enabled"] = self.dispatch_var.get()
        self.config["dispatch"]["color"] = self.dispatch_color
        self.config["dispatch"]["role_id"] = self.dispatch_role.get() or None

        filters = []
        for pattern, var in self.common_filter_vars.items():
            if var.get():
                filters.append(
                    {
                        "pattern": pattern,
                        "color": self.common_filter_colors[pattern].get(),
                        "role_id": self.common_filter_messages[pattern].get() or None,
                    }
                )

        filters += [
            f
            for f in self.config["filters"]
            if f["pattern"] not in COMMON_FILTERS.values()
        ]
        self.config["filters"] = filters

        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=4)
        self.update_filters_listbox()
        self.log("Config saved.")

    def update_filters_listbox(self):
        self.filters_listbox.delete(0, tk.END)
        for filt in self.config["filters"]:
            self.filters_listbox.insert(
                tk.END,
                f"{filt['pattern']} | Color: {filt['color']} | Role: {filt['role_id']}",
            )

    def add_filter(self):
        pattern = simpledialog.askstring("Custom Filter", "Enter regex pattern:")
        if not pattern:
            return
        color = colorchooser.askcolor(title="Pick color")[1]
        role = simpledialog.askstring("Role ID", "Enter role ID (or blank):")
        self.config["filters"].append(
            {
                "pattern": pattern,
                "color": int(color.lstrip("#"), 16) if color else 0x99AAB5,
                "role_id": role or None,
            }
        )
        self.update_filters_listbox()

    def remove_filter(self):
        selected = self.filters_listbox.curselection()
        if selected:
            index = selected[0]
            del self.config["filters"][index]
            self.update_filters_listbox()

    def pick_dispatch_color(self):
        color = colorchooser.askcolor(title="Pick Dispatch Color")[1]
        if color:
            self.dispatch_color = int(color.lstrip("#"), 16)

    def refresh_log(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as logf:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, logf.read())

    def log(self, message):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.feed_text["state"] = "normal"
        self.feed_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.feed_text["state"] = "disabled"
        self.feed_text.see(tk.END)
        with open(LOG_FILE, "a") as logf:
            logf.write(f"[{timestamp}] {message}\n")

    def validate_webhook(self, webhook):
        try:
            return requests.get(webhook).status_code == 200
        except:
            return False

    def start_listener(self):
        if self.listener_thread and self.listener_thread.is_alive():
            self.log("Listener already running.")
            return
        self.stop_event.clear()
        self.listener_thread = threading.Thread(target=self.listener)
        self.listener_thread.start()
        self.log("Listener started.")

    def stop_listener(self):
        self.stop_event.set()
        self.log("Stopping listener...")

    def listener(self):
        url = f"https://www.nationstates.net/api/region:{self.config['region']}"
        headers = {"User-Agent": "9005"}

        while not self.stop_event.is_set():
            try:
                response = requests.get(url, stream=True, headers=headers, timeout=60)
                client = sseclient.SSEClient(response)
                self.log("Connected to SSE feed.")
                for event in client.events():
                    if self.stop_event.is_set():
                        break
                    data = json.loads(event.data)
                    html = data.get("htmlStr", "")

                    flag_match = re.search(
                        r'<img src="([^"]+?)" class="miniflag"', html
                    )
                    flag_url = (
                        f"https://www.nationstates.net{flag_match.group(1).replace('.svg','.png')}"
                        if flag_match
                        else None
                    )

                    # ----- RMB CHECK -----
                    rmb_match = re.search(
                        r'<a href="/region=(.*?)/page=display_region_rmb\?postid=(\d+)',
                        html,
                    )
                    if rmb_match:
                        region = rmb_match.group(1)
                        post_id = rmb_match.group(2)
                        url_rmb = f"https://www.nationstates.net/cgi-bin/api.cgi?region={region}&q=messages&fromid={post_id}"
                        r = requests.get(url_rmb, headers={"User-Agent": "9005"})
                        xml_text = r.text

                        root = ET.fromstring(xml_text)
                        post_elem = root.find(".//POST")
                        if post_elem is not None:
                            message_text = post_elem.findtext("MESSAGE") or ""
                            nation = post_elem.findtext("NATION") or "Unknown"

                            message_text = (
                                message_text.replace("[i]", "*")
                                .replace("[/i]", "*")
                                .replace("[b]", "**")
                                .replace("[/b]", "**")
                            )

                            quotes = re.findall(
                                r"\[quote=(.*?);(\d+)](.*?)\[/quote]",
                                message_text,
                                re.DOTALL,
                            )
                            clean_text = re.sub(
                                r"\[quote=(.*?);(\d+)](.*?)\[/quote]",
                                "",
                                message_text,
                                flags=re.DOTALL,
                            ).strip()

                            # Determine color and role from filters
                            rmb_color = 3447003
                            mention = ""
                            rmb_role_id = ""
                            (
                                should_send,
                                rmb_color,
                                rmb_role_id,
                                event_type,
                            ) = self.event_matches(data)
                            if not should_send:
                                rmb_color = 3447003
                                rmb_role_id = None

                            mention = f"<@&{rmb_role_id}>" if rmb_role_id else ""

                            # RMB Posts
                            embed = {
                                "title": "New RMB Post",
                                "color": rmb_color,
                                "fields": [],
                                "footer": {
                                    "text": f"Posted by {nation} — https://www.nationstates.net/nation={nation.lower().replace(' ', '_')}"
                                },
                                "timestamp": datetime.utcfromtimestamp(
                                    data.get("time")
                                ).isoformat()
                                if data.get("time")
                                else None,
                                "url": f"https://www.nationstates.net/region={region}/page=display_region_rmb?postid={post_id}#p{post_id}",
                            }

                            if flag_url:
                                embed["thumbnail"] = {"url": flag_url}

                            for author, _, quote in quotes:
                                embed["fields"].append(
                                    {
                                        "name": f"Quoted from {author}",
                                        "value": quote.strip()[:1024],
                                        "inline": False,
                                    }
                                )

                            if clean_text:
                                embed["fields"].append(
                                    {
                                        "name": "Message",
                                        "value": clean_text[:1024],
                                        "inline": False,
                                    }
                                )

                            payload = {"content": mention, "embeds": [embed]}
                            response = requests.post(
                                self.config["webhook"], json=payload
                            )
                            if response.status_code not in (200, 204):
                                self.log(
                                    f"Failed to send RMB event: {response.status_code}"
                                )
                            else:
                                self.log("RMB event sent.")

                            continue  # skip normal processing

                            # ----- DISPATCH CHECK -----
                    message = data.get("str", "")

                    dispatch_match = re.search(
                        r'published\s+"<a href="page=dispatch/id=(\d+)">(.*?)</a>"\s+\(([^)]+)\)',
                        message,
                    )

                    if dispatch_match:
                        dispatch_id = dispatch_match.group(1)
                        dispatch_title = dispatch_match.group(2)
                        dispatch_type = dispatch_match.group(3)
                        dispatch_url = f"https://www.nationstates.net/page=dispatch/id={dispatch_id}"

                        # Grab the nation name
                        nation_match = re.search(r"@@(.*?)@@", message)
                        nation = nation_match.group(1) if nation_match else "Unknown"
                        nation_link = f"[{nation}](https://www.nationstates.net/nation={nation.lower().replace(' ', '_')})"

                        embed = {
                            "title": dispatch_title.upper(),
                            "url": dispatch_url,
                            "description": f"{nation_link} published a new dispatch ({dispatch_type}).",
                            "color": self.config["dispatch"]["color"],
                            "timestamp": datetime.utcfromtimestamp(
                                data.get("time")
                            ).isoformat()
                            if data.get("time")
                            else None,
                            "footer": {"text": f"{dispatch_type} Dispatch"},
                        }
                        if flag_url:
                            embed["thumbnail"] = {"url": flag_url}

                        mention = ""
                        if self.config["dispatch"]["role_id"]:
                            mention = f"<@&{self.config['dispatch']['role_id']}>"

                        payload = {"content": mention, "embeds": [embed]}
                        response = requests.post(self.config["webhook"], json=payload)
                        if response.status_code not in (200, 204):
                            self.log(
                                f"Failed to send dispatch event: {response.status_code}"
                            )
                        else:
                            self.log("Dispatch event sent.")

                        continue  # skip normal processing for dispatches

                    # ----- NORMAL EVENT CHECK -----
                    should_send, color, role_id, event_type = self.event_matches(data)
                    if should_send:
                        self.log(f"Matched ({event_type}): {data['str']}")
                        self.send_embed(data, color, role_id, event_type)
                    else:
                        self.log(f"Ignored: {data['str']}")
            except Exception as e:
                self.log(f"Connection error: {e}. Retrying in 10s.")
                time.sleep(10)

    def event_matches(self, data):
        str_data = data.get("str", "")
        if 'published "' in str_data.lower() and "dispatch" in str_data.lower():
            if self.config["dispatch"]["enabled"]:
                return (
                    True,
                    self.config["dispatch"]["color"],
                    self.config["dispatch"]["role_id"],
                    "dispatch",
                )
            else:
                return False, None, None, None
        for filt in self.config["filters"]:
            if re.search(filt["pattern"], str_data, re.IGNORECASE):
                return True, filt["color"], filt["role_id"], filt["pattern"]
        return False, None, None, None

    def smart_parse_event(self, event_str):
        match = re.match(r"(.*) in @@(\w+)@@, (.+)", event_str)
        if match:
            title = (
                f"{match.group(1)} in {match.group(2).capitalize().replace('_',' ')}"
            )
            description = match.group(3).capitalize()
        else:
            title = "NationStates Event"
            description = event_str
        return title, description

    def send_embed(self, data, color, role_id, event_type):
        title, description = self.smart_parse_event(data.get("str", "No description."))
        html = data.get("htmlStr", "")
        flag_match = re.search(r'<img src="([^"]+)" class="miniflag"', html)
        flag_url = (
            f"https://www.nationstates.net{flag_match.group(1).replace('.svg','.png')}"
            if flag_match
            else None
        )

        # Apply hyperlinking to title and description
        title = self.hyperlink(title)
        description = self.hyperlink(description)

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "footer": {"text": f"Event ID: {data.get('id', 'N/A')}"},
            "timestamp": datetime.utcfromtimestamp(data.get("time")).isoformat()
            if data.get("time")
            else None,
        }

        if flag_url:
            embed["thumbnail"] = {"url": flag_url}

        mention = f"<@&{role_id}>" if role_id else ""
        payload = {"content": mention, "embeds": [embed]}
        response = requests.post(self.config["webhook"], json=payload)
        if response.status_code not in (200, 204):
            self.log(f"Failed to send event: {response.status_code}")
        else:
            self.log(f"Event sent ({event_type})")


if __name__ == "__main__":
    root = tk.Tk()
    app = Elderscry(root)
    root.mainloop()
