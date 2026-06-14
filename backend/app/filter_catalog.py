"""Curated catalog of popular filter lists and blockable services.

These are presented in the UI so an admin can enable well-known blocklists /
allowlists with one click instead of pasting URLs. Blocklist URLs prefer the
AdGuard Hostlists Registry stable asset URLs where available, which are the same
sources AdGuard Home offers in its own UI.
"""
from __future__ import annotations

from .models import FilterKind

# Each entry: name, url, kind, description, recommended
FILTER_CATALOG: list[dict] = [
    # ---- Blocklists -------------------------------------------------------
    {
        "name": "AdGuard DNS filter",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        "kind": FilterKind.blocklist,
        "description": "AdGuard's own list — ads and trackers. Good default.",
        "recommended": True,
    },
    {
        "name": "AdAway Default Blocklist",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
        "kind": FilterKind.blocklist,
        "description": "Mobile ads and trackers. Small and well-maintained.",
        "recommended": False,
    },
    {
        "name": "Peter Lowe's Blocklist",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
        "kind": FilterKind.blocklist,
        "description": "Ads and tracking servers (pgl.yoyo.org).",
        "recommended": False,
    },
    {
        "name": "Dan Pollock's List",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
        "kind": FilterKind.blocklist,
        "description": "A balanced, low-false-positive hosts list (someonewhocares).",
        "recommended": False,
    },
    {
        "name": "OISD Blocklist Small",
        "url": "https://small.oisd.nl",
        "kind": FilterKind.blocklist,
        "description": "Lean, all-round ad/tracker list with few false positives.",
        "recommended": True,
    },
    {
        "name": "OISD Blocklist Big",
        "url": "https://big.oisd.nl",
        "kind": FilterKind.blocklist,
        "description": "Comprehensive ads, tracking, malware and phishing.",
        "recommended": False,
    },
    {
        "name": "HaGeZi Multi PRO",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "kind": FilterKind.blocklist,
        "description": "Aggressive, well-curated ads/tracking/malware. Popular.",
        "recommended": True,
    },
    {
        "name": "StevenBlack Unified Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "kind": FilterKind.blocklist,
        "description": "Unified ads + malware hosts file. Very widely used.",
        "recommended": False,
    },
    {
        "name": "1Hosts (Lite)",
        "url": "https://o0.pages.dev/Lite/adblock.txt",
        "kind": FilterKind.blocklist,
        "description": "Lightweight ad/tracker protection with low breakage.",
        "recommended": False,
    },
    {
        "name": "Phishing Army (Extended)",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "kind": FilterKind.blocklist,
        "description": "Phishing domains — security-focused.",
        "recommended": False,
    },
    {
        "name": "Malicious URL Blocklist (URLHaus)",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
        "kind": FilterKind.blocklist,
        "description": "Domains serving malware, from abuse.ch URLHaus.",
        "recommended": False,
    },
    {
        "name": "AdGuard CNAME-cloaked Trackers",
        "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt",
        "kind": FilterKind.blocklist,
        "description": "Blocks trackers that hide behind CNAME records.",
        "recommended": False,
    },
    # ---- Allowlists -------------------------------------------------------
    {
        "name": "HaGeZi Allowlist (Referral)",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
        "kind": FilterKind.allowlist,
        "description": "Unblocks referral/affiliate domains some lists break.",
        "recommended": False,
    },
    {
        "name": "anudeepND Allowlist",
        "url": "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
        "kind": FilterKind.allowlist,
        "description": "Common false positives kept working (CDNs, logins).",
        "recommended": True,
    },
]


# Popular blockable services. service_id MUST match AdGuard's known service ids.
SERVICE_CATALOG: list[dict] = [
    {"service_id": "youtube", "name": "YouTube", "recommended": True},
    {"service_id": "tiktok", "name": "TikTok", "recommended": True},
    {"service_id": "facebook", "name": "Facebook", "recommended": True},
    {"service_id": "instagram", "name": "Instagram", "recommended": True},
    {"service_id": "twitter", "name": "X (Twitter)", "recommended": False},
    {"service_id": "snapchat", "name": "Snapchat", "recommended": False},
    {"service_id": "reddit", "name": "Reddit", "recommended": False},
    {"service_id": "discord", "name": "Discord", "recommended": False},
    {"service_id": "telegram", "name": "Telegram", "recommended": False},
    {"service_id": "whatsapp", "name": "WhatsApp", "recommended": False},
    {"service_id": "netflix", "name": "Netflix", "recommended": False},
    {"service_id": "twitch", "name": "Twitch", "recommended": False},
    {"service_id": "disneyplus", "name": "Disney+", "recommended": False},
    {"service_id": "hulu", "name": "Hulu", "recommended": False},
    {"service_id": "spotify", "name": "Spotify", "recommended": False},
    {"service_id": "steam", "name": "Steam", "recommended": False},
    {"service_id": "epic_games", "name": "Epic Games", "recommended": False},
    {"service_id": "roblox", "name": "Roblox", "recommended": True},
    {"service_id": "pinterest", "name": "Pinterest", "recommended": False},
    {"service_id": "amazon", "name": "Amazon", "recommended": False},
    {"service_id": "ebay", "name": "eBay", "recommended": False},
    {"service_id": "tinder", "name": "Tinder", "recommended": False},
    {"service_id": "zoom", "name": "Zoom", "recommended": False},
]
