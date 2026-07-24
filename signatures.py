"""
Tracker signature database for CIPA / consent auditing.

Each signature maps a URL/domain pattern to a vendor, a category, and a
CIPA-relevance weight. The CIPA "wiretapping" theories center on third-party
interception of a visitor's communications with a site. So the categories that
carry the most litigation risk are the ones that transmit user interaction data
to a third party in real time: session replay, chat, and pixels that capture
form/field or event data.

risk scale (per finding, before pre-consent multiplier):
  10 = high      (session replay, third-party chat capturing messages)
   7 = elevated  (ad/marketing pixels capturing events)
   4 = moderate  (analytics)
   1 = low        (tag managers, CDNs, fonts -- context only)
"""

# category -> base CIPA risk weight
CATEGORY_RISK = {
    "session_replay": 10,
    "chat_widget": 10,
    "ad_pixel": 7,
    "analytics": 4,
    "tag_manager": 1,
    "other": 1,
}

# category -> human-readable CIPA rationale
CATEGORY_RATIONALE = {
    "session_replay": (
        "Session-replay scripts record keystrokes, mouse movement, and form "
        "input and stream them to a third party. This is the fact pattern in "
        "the leading CIPA 'wiretap' cases (Javier v. Assurance IQ line)."
    ),
    "chat_widget": (
        "Third-party chat/agent widgets can intercept the contents of a "
        "visitor's messages in real time. Alleged as unlawful recording of "
        "communications under CIPA s.631/632."
    ),
    "ad_pixel": (
        "Marketing pixels transmit page views and event/conversion data "
        "(sometimes including form fields) to an ad network before consent."
    ),
    "analytics": (
        "Analytics beacons transmit behavioral data to a third party. Lower "
        "risk than replay/chat but still consent-relevant, especially if it "
        "fires before a consent choice."
    ),
    "tag_manager": (
        "Tag managers inject other tags. Not itself a wiretap risk but is the "
        "mechanism through which risky tags load -- key for remediation."
    ),
    "other": "Third-party request; classified for inventory completeness.",
}

# Each entry: substring/domain patterns that identify the vendor.
# Matching is done against the full request URL (lowercased).
SIGNATURES = [
    # --- Session replay (highest CIPA exposure) ---
    {"vendor": "FullStory",      "category": "session_replay", "patterns": ["fullstory.com", "fs.js", "edge.fullstory.com"]},
    {"vendor": "Hotjar",         "category": "session_replay", "patterns": ["hotjar.com", "static.hotjar", "script.hotjar"]},
    {"vendor": "Microsoft Clarity","category": "session_replay","patterns": ["clarity.ms", "c.clarity.ms"]},
    {"vendor": "LogRocket",      "category": "session_replay", "patterns": ["logrocket.com", "lr-ingest", "cdn.logrocket"]},
    {"vendor": "Mouseflow",      "category": "session_replay", "patterns": ["mouseflow.com"]},
    {"vendor": "SessionCam/Glassbox","category":"session_replay","patterns": ["sessioncam.com", "glassbox", "clicktale"]},
    {"vendor": "Quantum Metric", "category": "session_replay", "patterns": ["quantummetric.com"]},
    {"vendor": "Contentsquare",  "category": "session_replay", "patterns": ["contentsquare.net", "content-square"]},
    {"vendor": "Smartlook",      "category": "session_replay", "patterns": ["smartlook.com"]},
    {"vendor": "Inspectlet",     "category": "session_replay", "patterns": ["inspectlet.com"]},

    # --- Chat widgets (real-time message interception) ---
    {"vendor": "Drift",          "category": "chat_widget", "patterns": ["drift.com", "js.driftt.com"]},
    {"vendor": "Intercom",       "category": "chat_widget", "patterns": ["intercom.io", "intercomcdn.com", "widget.intercom"]},
    {"vendor": "Zendesk Chat",   "category": "chat_widget", "patterns": ["zopim.com", "zdassets.com", "zendesk.com/embeddable"]},
    {"vendor": "LiveChat",       "category": "chat_widget", "patterns": ["livechatinc.com", "livechat.com"]},
    {"vendor": "Tidio",          "category": "chat_widget", "patterns": ["tidio.co", "tidiochat"]},
    {"vendor": "Salesforce/LivePerson","category":"chat_widget","patterns": ["liveperson.net", "lpsnmedia", "salesforceliveagent"]},
    {"vendor": "Genesys",        "category": "chat_widget", "patterns": ["genesys.com", "genesyscloud"]},
    {"vendor": "HubSpot Chat",   "category": "chat_widget", "patterns": ["js.hs-scripts.com", "hubspot.com/conversations"]},

    # --- Ad / marketing pixels ---
    {"vendor": "Meta Pixel",     "category": "ad_pixel", "patterns": ["connect.facebook.net", "facebook.com/tr", "fbevents.js"]},
    {"vendor": "TikTok Pixel",   "category": "ad_pixel", "patterns": ["analytics.tiktok.com", "tiktok.com/i18n/pixel"]},
    {"vendor": "Google Ads/DoubleClick","category":"ad_pixel","patterns": ["googleadservices.com", "doubleclick.net", "googlesyndication.com", "google.com/ads"]},
    {"vendor": "LinkedIn Insight","category": "ad_pixel", "patterns": ["snap.licdn.com", "px.ads.linkedin.com", "linkedin.com/li"]},
    {"vendor": "Pinterest Tag",  "category": "ad_pixel", "patterns": ["ct.pinterest.com", "s.pinimg.com/ct"]},
    {"vendor": "Twitter/X Pixel","category": "ad_pixel", "patterns": ["static.ads-twitter.com", "analytics.twitter.com", "t.co/i/adsct"]},
    {"vendor": "Snap Pixel",     "category": "ad_pixel", "patterns": ["sc-static.net", "tr.snapchat.com"]},
    {"vendor": "Criteo",         "category": "ad_pixel", "patterns": ["criteo.com", "criteo.net"]},
    {"vendor": "The Trade Desk", "category": "ad_pixel", "patterns": ["adsrvr.org"]},
    {"vendor": "Bing/Microsoft Ads","category":"ad_pixel","patterns": ["bat.bing.com"]},

    # --- Analytics ---
    {"vendor": "Google Analytics","category": "analytics", "patterns": ["google-analytics.com", "googletagmanager.com/gtag", "/g/collect", "region1.google-analytics"]},
    {"vendor": "Segment",        "category": "analytics", "patterns": ["cdn.segment.com", "api.segment.io"]},
    {"vendor": "Mixpanel",       "category": "analytics", "patterns": ["mixpanel.com", "cdn.mxpnl.com"]},
    {"vendor": "Amplitude",      "category": "analytics", "patterns": ["amplitude.com", "api2.amplitude"]},
    {"vendor": "Heap",           "category": "analytics", "patterns": ["heap.io", "heapanalytics.com"]},
    {"vendor": "Adobe Analytics","category": "analytics", "patterns": ["omtrdc.net", "2o7.net", "demdex.net", "adobedtm.com"]},
    {"vendor": "Pendo",          "category": "analytics", "patterns": ["pendo.io"]},
    {"vendor": "Matomo",         "category": "analytics", "patterns": ["matomo", "piwik"]},

    # --- Tag managers ---
    {"vendor": "Google Tag Manager","category":"tag_manager","patterns": ["googletagmanager.com/gtm.js", "googletagmanager.com/ns"]},
    {"vendor": "Tealium",        "category": "tag_manager", "patterns": ["tags.tiqcdn.com", "tealium"]},
    {"vendor": "Adobe Launch",   "category": "tag_manager", "patterns": ["assets.adobedtm.com/launch"]},
    {"vendor": "Ensighten",      "category": "tag_manager", "patterns": ["ensighten.com"]},
]

# Consent Management Platform signatures -- presence detection.
CMP_SIGNATURES = [
    {"vendor": "OneTrust",     "patterns": ["onetrust.com", "cdn.cookielaw.org", "otSDKStub"]},
    {"vendor": "Cookiebot",    "patterns": ["cookiebot.com", "consent.cookiebot"]},
    {"vendor": "TrustArc",     "patterns": ["trustarc.com", "consent.truste"]},
    {"vendor": "Osano",        "patterns": ["osano.com", "cmp.osano"]},
    {"vendor": "Usercentrics", "patterns": ["usercentrics.eu", "app.usercentrics"]},
    {"vendor": "Didomi",       "patterns": ["didomi.io", "sdk.privacy-center"]},
    {"vendor": "Quantcast",    "patterns": ["quantcast.mgr.consensu", "quantcast.com/choice"]},
    {"vendor": "CookieYes",    "patterns": ["cookieyes.com"]},
    {"vendor": "Termly",       "patterns": ["termly.io"]},
    {"vendor": "Freshpaint",   "patterns": ["freshpaint.io", "perfalytics.com"]},
]


def classify(url: str):
    """Return (vendor, category) for a URL, or (None, None) if unknown."""
    u = url.lower()
    for sig in SIGNATURES:
        if any(p in u for p in sig["patterns"]):
            return sig["vendor"], sig["category"]
    return None, None


def detect_cmp(url: str):
    """Return CMP vendor name if the URL matches a known CMP, else None."""
    u = url.lower()
    for sig in CMP_SIGNATURES:
        if any(p in u for p in sig["patterns"]):
            return sig["vendor"]
    return None
