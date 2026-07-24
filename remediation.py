"""
Remediation recommendations, centered on routing tracking through Freshpaint's
consent-gating / data-governance layer.

Freshpaint's relevant capability set (as a compliance-tooling vendor): it sits
between a site and its downstream marketing/analytics destinations, lets tags be
gated on consent state, and can block or transform data before it reaches a
third party. The recommendations below map each finding category to how that
control applies.
"""

FRESHPAINT_REMEDIATION = {
    "session_replay": {
        "action": "Gate session-replay behind explicit consent; disable field capture by default.",
        "freshpaint": (
            "Route the replay tool as a Freshpaint destination so it only "
            "activates after opt-in. Use Freshpaint's data-blocking rules to "
            "strip form-field and keystroke capture, which is the specific "
            "content that drives CIPA replay claims."
        ),
        "priority": "Critical",
    },
    "chat_widget": {
        "action": "Disclose recording in the chat UI and load the widget only post-consent.",
        "freshpaint": (
            "Defer chat-widget load through Freshpaint consent gating, and add "
            "an in-widget recording/third-party disclosure. Addresses the "
            "'undisclosed interception of the conversation' theory."
        ),
        "priority": "Critical",
    },
    "ad_pixel": {
        "action": "Do not fire ad pixels before consent; filter PII/form data from payloads.",
        "freshpaint": (
            "Send pixel events server-side through Freshpaint with consent "
            "enforcement, and use PII-filtering rules so form fields and email "
            "hashes are not transmitted pre-consent."
        ),
        "priority": "High",
    },
    "analytics": {
        "action": "Hold analytics beacons until a consent choice is made.",
        "freshpaint": (
            "Wire analytics as Freshpaint destinations gated on consent state "
            "so no beacon fires on initial load before the visitor chooses."
        ),
        "priority": "Medium",
    },
    "tag_manager": {
        "action": "Ensure the tag manager itself does not auto-fire downstream tags pre-consent.",
        "freshpaint": (
            "Move destination management out of client-side GTM into "
            "Freshpaint, so consent state -- not tag-manager triggers -- "
            "controls what loads."
        ),
        "priority": "Medium",
    },
    "other": {
        "action": "Review third-party request for necessity.",
        "freshpaint": "Inventory in Freshpaint's destination catalog and gate if it collects behavioral data.",
        "priority": "Low",
    },
}

NO_CMP_REMEDIATION = {
    "action": "No consent management platform detected -- trackers fire ungated on load.",
    "freshpaint": (
        "This is the highest-leverage fix. With no CMP present, every "
        "third-party tracker is firing before any consent opportunity, which "
        "is the core CIPA fact pattern. Deploy a consent banner and route all "
        "tracking destinations through Freshpaint so firing is conditioned on "
        "the visitor's choice."
    ),
    "priority": "Critical",
}


def build_recommendations(site_result):
    """Given one scan result, return an ordered list of remediation items."""
    recs = []
    if not site_result.get("has_cmp") and site_result.get("trackers"):
        recs.append({"scope": "site", "title": "No consent management detected", **NO_CMP_REMEDIATION})

    seen = set()
    # One rec per category, driven by highest-risk finding in that category.
    for f in site_result.get("trackers", []):
        cat = f["category"]
        if cat in seen:
            continue
        seen.add(cat)
        rem = FRESHPAINT_REMEDIATION.get(cat, FRESHPAINT_REMEDIATION["other"])
        vendors = [t["vendor"] for t in site_result["trackers"] if t["category"] == cat]
        recs.append({
            "scope": "category",
            "title": f"{cat.replace('_',' ').title()} detected: {', '.join(vendors)}",
            **rem,
        })
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda r: order.get(r["priority"], 9))
    return recs
