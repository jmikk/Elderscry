 Elderscry - NationStates SSE Event Monitor

A powerful, GUI tool for monitoring NationStates regions, RMB posts, dispatches, and events in real-time with webhook alerts to Discord.

📝 Features

Connects to NationStates SSE feed for your region

Sends Discord webhook alerts for:

RMB posts

Dispatches

Embassy activity

Nation reclassifications

RO power changes

Flag/banner changes

Banjections, unban actions, and more

Configurable filters by regex with color and role mentions

Easy to use GUI with tabs:

Info

General

Embassies

Regional Changes

RO Actions

Nation Changes

Maps

Miscellaneous (Custom Filters)

Auto hyperlinking of nations and regions in alerts

Supports role pings for certain events

Live feed viewer and persistent logging

⚙ Requirements

Standard Library (no install needed):

json

os

re

time

threading

datetime

tkinter (Note: On macOS, you may need to install tkinter separately)

xml.etree.ElementTree

Install via pip:

pip install requests
pip install sseclient-py

🔧 Usage

1️⃣ Install dependencies

pip install requests sseclient-py

2️⃣ Run the app

python Elderscry.py

3️⃣ Setup your config

Region: Name of the region you want to monitor

Webhook: Your Discord webhook URL

User Agent: 

4️⃣ Configure filters

Choose which event types to monitor

Pick colors and mention roles if desired

Use the Save Config button (now available across all tabs)

5️⃣ Start Listener

Go to the Live Feed tab

Click Start Listener

🕵 Known Issues / Notes

On macOS, tkinter may not always be installed by default. Install via Homebrew or ensure Python includes it.

Rapid incoming events may cause slight UI delay (currently mitigated by using threading and throttling).

RMB role mentions and color pickers work, but occasionally macOS Tkinter may need a window resize to refresh clickable areas.

🪄 Mystical Identity

Your bot’s mystical-themed names:

NS Sentinel (default professional name)

Elderscry (fantasy/mystical name)

The Aetherwatch (mystic arcane name)

Pick whichever matches the theme of your NS region or Discord aesthetic!

📚 License

MIT License .

🧠 Credits

Created and maintained by 9005.



May the Elderscry reveal all whispers of the realm...

