"""
Freshpaint CIPA / Consent Audit -- Streamlit compliance dashboard.

Run:  streamlit run app.py

Paste a list of target sites (one per line). The app loads each in a headless
browser, inventories third-party trackers and cookies, checks for pre-consent
firing and CMP presence, scores CIPA exposure, and produces Freshpaint-centered
remediation guidance. Export results as CSV.
"""
import io
import csv
import pandas as pd
import streamlit as st

from scanner import scan_many, ensure_chromium, PLAYWRIGHT_AVAILABLE
from remediation import build_recommendations

st.set_page_config(page_title="Freshpaint CIPA Consent Audit", page_icon="🛡️", layout="wide")


# ---- Bootstrap: install Chromium browser binary on first load ----
# Streamlit Cloud installs the playwright *Python* package via requirements.txt
# but does NOT run `playwright install chromium`.  This cached call fetches the
# browser binary once per app lifecycle so live scanning works.
@st.cache_resource
def _bootstrap_chromium():
    return ensure_chromium()

_chromium_ready = _bootstrap_chromium()

st.title("🛡️ Freshpaint CIPA / Consent Audit")
st.caption(
    "Bulk-scan sites for third-party trackers that fire before consent — the "
    "core fact pattern in CIPA wiretapping claims — and get Freshpaint "
    "remediation guidance. Passive load-time analysis; no forms are submitted."
)

# ---- Scanner mode indicator ----
if not PLAYWRIGHT_AVAILABLE:
    st.warning(
        "⚠️ **Demo mode (Playwright not installed).** Scans will use simulated "
        "results generated from the tracker signature database. Install "
        "Playwright + Chromium for live site scanning."
    )
elif not _chromium_ready:
    st.warning(
        "⚠️ **Demo mode (Chromium unavailable).** Playwright is installed but the "
        "Chromium browser binary could not be launched. Scans will use simulated "
        "results. Run `playwright install chromium` to enable live scanning."
    )
else:
    st.success("✅ **Live scanning mode** — headless Chromium is ready.")

with st.sidebar:
    st.header("Scan settings")
    settle = st.slider("Page settle time (ms)", 1500, 8000, 3500, 500,
                       help="How long to wait after load for tag-managed scripts to fire.")
    st.markdown("---")
    st.markdown(
        "**How it works**\n\n"
        "1. Real headless Chromium load\n"
        "2. Intercept every 3rd-party request + cookie\n"
        "3. Flag trackers firing pre-consent\n"
        "4. Detect CMP presence\n"
        "5. Score & map to Freshpaint fixes"
    )
    st.markdown("---")
    st.info("Scan sites you own or are authorized to audit.")

default = "example.com\nwww.hotjar.com"
urls_raw = st.text_area("Target sites (one per line)", value=default, height=140)

col_a, col_b = st.columns([1, 5])
run = col_a.button("Run scan", type="primary")

if run:
    urls = [u.strip() for u in urls_raw.splitlines() if u.strip()]
    if not urls:
        st.warning("Enter at least one site.")
        st.stop()

    prog = st.progress(0.0, text="Starting…")
    status = st.empty()
    collected = {}

    def _cb(done, total, res):
        prog.progress(done / total, text=f"Scanned {done}/{total}: {res['url']}")

    results = scan_many(urls, settle_ms=settle, progress=_cb)
    prog.empty(); status.empty()

    # ---- Portfolio summary ----
    scored = [r for r in results if r.get("score") is not None]
    if scored:
        avg = round(sum(r["score"] for r in scored) / len(scored), 1)
        crit = sum(1 for r in scored for f in r["trackers"]
                   if f["category"] in ("session_replay", "chat_widget"))
        no_cmp = sum(1 for r in scored if not r["has_cmp"] and r["trackers"])
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Sites scanned", len(scored))
        m2.metric("Avg compliance score", avg)
        m3.metric("High-risk trackers", crit,
                  help="Session-replay + chat findings")
        m4.metric("Sites w/ no CMP", no_cmp)

    st.markdown("## Results")

    # ---- Export data accumulator ----
    export_rows = []

    for r in results:
        header = f"**{r['url']}**"
        if r.get("error"):
            st.error(f"{header} — scan error: {r['error']}")
            continue

        grade = r["grade"]
        badge = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(grade, "⚪")
        with st.expander(f"{badge}  {r['url']}  —  Grade {grade}  (score {r['score']})",
                         expanded=len(results) <= 3):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Score", r["score"])
            c2.metric("Trackers", len(r["trackers"]))
            c3.metric("CMP", ", ".join(r["cmp_detected"]) if r["has_cmp"] else "None")
            c4.metric("Cookies", r["cookie_count"])

            if r["trackers"]:
                st.markdown("#### Trackers detected")
                df = pd.DataFrame([{
                    "Vendor": f["vendor"],
                    "Category": f["category"].replace("_", " ").title(),
                    "Requests": f["request_count"],
                    "Pre-consent": "⚠️ Yes" if f["pre_consent"] else "No",
                    "Risk": f["risk"],
                } for f in r["trackers"]])
                st.dataframe(df, use_container_width=True, hide_index=True)

                with st.container():
                    st.markdown("#### CIPA rationale")
                    shown = set()
                    for f in r["trackers"]:
                        if f["category"] in shown:
                            continue
                        shown.add(f["category"])
                        st.markdown(f"- **{f['category'].replace('_',' ').title()}** — {f['rationale']}")

                st.markdown("#### 🔧 Freshpaint remediation")
                for rec in build_recommendations(r):
                    tag = {"Critical": "🔴", "High": "🟠",
                           "Medium": "🟡", "Low": "⚪"}.get(rec["priority"], "")
                    st.markdown(f"**{tag} {rec['priority']} — {rec['title']}**")
                    st.markdown(f"- Action: {rec['action']}")
                    st.markdown(f"- With Freshpaint: {rec['freshpaint']}")
            else:
                st.success("No consent-relevant third-party trackers detected on load.")

            for f in r["trackers"]:
                export_rows.append({
                    "site": r["url"], "score": r["score"], "grade": r["grade"],
                    "has_cmp": r["has_cmp"], "cmp": ";".join(r["cmp_detected"]),
                    "vendor": f["vendor"], "category": f["category"],
                    "pre_consent": f["pre_consent"], "risk": f["risk"],
                })
            if not r["trackers"]:
                export_rows.append({
                    "site": r["url"], "score": r["score"], "grade": r["grade"],
                    "has_cmp": r["has_cmp"], "cmp": ";".join(r["cmp_detected"]),
                    "vendor": "", "category": "", "pre_consent": "", "risk": 0,
                })

    if export_rows:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(export_rows[0].keys()))
        w.writeheader(); w.writerows(export_rows)
        st.download_button("⬇️ Download CSV report", buf.getvalue(),
                           file_name="cipa_audit_report.csv", mime="text/csv")
