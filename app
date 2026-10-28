"""NetTrace - IP Geolocation & WHOIS Network Tracer (Streamlit, no API keys)."""

import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import folium
import pandas as pd
import requests
import streamlit as st
import whois
from streamlit_folium import st_folium

# --------------------------------------------------------------------------- #
# Page setup
# --------------------------------------------------------------------------- #
st.set_page_config(page_title="NetTrace", page_icon="🛰️", layout="wide")

GEO_URL = "http://ip-api.com/json/{ip}"  # free tier is HTTP-only, server-side call
GEO_FIELDS = (
    "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,"
    "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def clean_input(raw: str) -> str:
    """Reduce URLs / host:port strings to a bare hostname or IP."""
    value = raw.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "//" + value  # lets urlparse treat it as a netloc
    host = urlparse(value).hostname or ""
    return host.strip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_to_ipv4(target: str) -> str:
    """Return an IPv4 address for a domain, or the IP itself."""
    if is_ip(target):
        return target
    return socket.gethostbyname(target)


@st.cache_data(ttl=600, show_spinner=False)
def fetch_geo(ip: str) -> dict:
    resp = requests.get(GEO_URL.format(ip=ip), params={"fields": GEO_FIELDS}, timeout=10)
    resp.raise_for_status()
    return resp.json()


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_whois(domain: str) -> dict:
    """Try the domain, then walk up to its parent domain (for subdomains)."""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)] or [domain]
    for candidate in candidates:
        try:
            data = whois.whois(candidate)
            if data and (data.get("domain_name") or data.get("registrar")):
                result = dict(data)
                result["_queried"] = candidate
                return result
        except Exception:
            continue
    return {}


def first(value):
    """python-whois often returns lists; take the first item."""
    if isinstance(value, (list, tuple, set)):
        value = next(iter(value), None)
    return value


def fmt_date(value) -> str:
    value = first(value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value) if value else "N/A"


def days_until(value):
    value = first(value)
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (value - datetime.now(timezone.utc)).days


def build_map(lat: float, lon: float, label: str, popup: str) -> folium.Map:
    fmap = folium.Map(location=[lat, lon], zoom_start=9, tiles="CartoDB positron")
    folium.Marker(
        [lat, lon],
        tooltip=label,
        popup=folium.Popup(popup, max_width=250),
        icon=folium.Icon(color="red", icon="globe", prefix="fa"),
    ).add_to(fmap)
    folium.Circle([lat, lon], radius=15000, color="#e5484d", fill=True, fill_opacity=0.12).add_to(fmap)
    return fmap


def flag(value: bool) -> str:
    return "⚠️ Yes" if value else "✅ No"


# --------------------------------------------------------------------------- #
# Header + input
# --------------------------------------------------------------------------- #
st.title("🛰️ NetTrace")
st.caption("IP geolocation, routing metadata and WHOIS intelligence — no API keys required.")

with st.form("trace_form"):
    c1, c2 = st.columns([5, 1])
    raw_target = c1.text_input(
        "Target",
        placeholder="github.com  or  8.8.8.8",
        label_visibility="collapsed",
    )
    submitted = c2.form_submit_button("Trace", use_container_width=True, type="primary")

if not submitted:
    st.info("Enter a domain or IPv4 address above and press **Trace**.")
    st.stop()

target = clean_input(raw_target)
if not target:
    st.warning("Please enter a domain name or IP address.")
    st.stop()

# --------------------------------------------------------------------------- #
# Resolve + geolocate
# --------------------------------------------------------------------------- #
input_is_ip = is_ip(target)

try:
    with st.spinner("Resolving target..."):
        ip = resolve_to_ipv4(target)
except socket.gaierror:
    st.error(f"Could not resolve **{target}**. Check the spelling or your connection.")
    st.stop()

try:
    with st.spinner("Querying geolocation..."):
        geo = fetch_geo(ip)
except requests.RequestException as exc:
    st.error(f"Geolocation service unreachable: {exc}")
    st.stop()

if geo.get("status") != "success":
    st.error(f"Lookup failed for **{ip}**: {geo.get('message', 'unknown error')}")
    st.stop()

asn, _, as_name = (geo.get("as") or "").partition(" ")
location = ", ".join(p for p in (geo.get("city"), geo.get("regionName"), geo.get("country")) if p)

# --------------------------------------------------------------------------- #
# Metric cards
# --------------------------------------------------------------------------- #
st.subheader(f"Results for `{target}`")
m1, m2, m3, m4 = st.columns(4)
m1.metric("IP Address", ip)
m2.metric("ASN", asn or "N/A")
m3.metric("Country", f"{geo.get('country', 'N/A')} ({geo.get('countryCode', '')})")
m4.metric("Timezone", geo.get("timezone", "N/A"))

st.divider()

# --------------------------------------------------------------------------- #
# 2-column dashboard: details | map
# --------------------------------------------------------------------------- #
left, right = st.columns(2, gap="large")

with left:
    st.markdown("#### 🌐 Network & Routing")
    net_rows = {
        "ISP": geo.get("isp"),
        "Organization": geo.get("org"),
        "ASN": asn,
        "AS Name": geo.get("asname") or as_name,
        "Reverse DNS": geo.get("reverse") or "N/A",
    }
    st.table(pd.DataFrame({"Field": net_rows.keys(), "Value": [v or "N/A" for v in net_rows.values()]}).set_index("Field"))

    st.markdown("#### 📍 Location")
    loc_rows = {
        "City": geo.get("city"),
        "Region": geo.get("regionName"),
        "Postal Code": geo.get("zip"),
        "Latitude": geo.get("lat"),
        "Longitude": geo.get("lon"),
    }
    st.table(pd.DataFrame({"Field": loc_rows.keys(), "Value": [str(v) if v not in (None, "") else "N/A" for v in loc_rows.values()]}).set_index("Field"))

    st.markdown("#### 🚩 Network Flags")
    f1, f2, f3 = st.columns(3)
    f1.metric("Proxy / VPN", flag(geo.get("proxy", False)))
    f2.metric("Hosting / DC", flag(geo.get("hosting", False)))
    f3.metric("Mobile", flag(geo.get("mobile", False)))

with right:
    st.markdown("#### 🗺️ Map")
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is not None and lon is not None:
        popup = f"<b>{target}</b><br>{ip}<br>{location}"
        st_folium(build_map(lat, lon, ip, popup), height=430, use_container_width=True, returned_objects=[])
        st.caption("Geolocation is approximate and usually reflects the ISP's location, not the exact device.")
    else:
        st.warning("No coordinates available for this IP.")

# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
st.divider()
st.markdown("#### 📇 WHOIS Domain Intelligence")

whois_data = {}
if input_is_ip:
    st.info("WHOIS ownership data applies to domain names. Enter a domain to see registrar details.")
else:
    with st.spinner("Querying WHOIS..."):
        whois_data = fetch_whois(target)

    if not whois_data:
        st.warning("No WHOIS record found (the TLD may restrict WHOIS or the registry is rate-limiting).")
    else:
        if whois_data.get("_queried") != target:
            st.caption(f"Showing WHOIS for parent domain `{whois_data['_queried']}`.")

        remaining = days_until(whois_data.get("expiration_date"))
        w1, w2, w3, w4 = st.columns(4)
        w1.metric("Registrar", first(whois_data.get("registrar")) or "N/A")
        w2.metric("Created", fmt_date(whois_data.get("creation_date")))
        w3.metric("Expires", fmt_date(whois_data.get("expiration_date")))
        w4.metric("Days Left", f"{remaining:,}" if remaining is not None else "N/A")

        owner = first(whois_data.get("org")) or first(whois_data.get("name")) or "Redacted / Private"
        ns = whois_data.get("name_servers") or []
        ns = sorted({str(n).lower() for n in (ns if isinstance(ns, (list, set, tuple)) else [ns])})
        status = first(whois_data.get("status")) or "N/A"

        st.table(
            pd.DataFrame(
                {
                    "Field": ["Domain Owner", "Owner Country", "Status", "Name Servers"],
                    "Value": [
                        owner,
                        first(whois_data.get("country")) or "N/A",
                        str(status),
                        ", ".join(ns) if ns else "N/A",
                    ],
                }
            ).set_index("Field")
        )

# --------------------------------------------------------------------------- #
# Raw data
# --------------------------------------------------------------------------- #
with st.expander("🔎 View raw data"):
    st.markdown("**Geolocation (JSON)**")
    st.json(geo)
    if whois_data:
        st.markdown("**WHOIS (JSON)**")
        st.json({k: str(v) for k, v in whois_data.items()})

st.caption("Data: ip-api.com (free tier, ~45 requests/min) · WHOIS via python-whois")
