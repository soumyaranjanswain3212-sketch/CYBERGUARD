from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse
from uuid import uuid4


URGENT_TERMS = (
    "urgent", "immediately", "within 24 hours", "action required", "suspended",
    "verify now", "final warning", "act now",
)
CREDENTIAL_TERMS = (
    "password", "login", "log in", "sign in", "credential", "verify your account",
    "account details", "one-time code", "otp",
)
AUTHORITY_TERMS = (
    "ceo", "director", "principal", "government", "bank", "payroll", "finance",
    "police", "university", "administrator",
)
PAYMENT_TERMS = ("wire transfer", "gift card", "payment", "bank details", "transfer funds", "new account")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly"}
RISK_LEVELS = ((85, "Critical"), (65, "High"), (40, "Medium"), (15, "Low"))


def _matches(text: str, terms: tuple[str, ...]) -> list[str]:
    normalized = text.casefold()
    return [term for term in terms if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", normalized)]


def _domain(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return (urlparse(candidate).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


def _url_indicators(url: str) -> list[str]:
    domain = _domain(url)
    indicators: list[str] = []
    if not domain:
        return indicators
    if domain in SHORTENERS:
        indicators.append("URL uses a public link-shortening service")
    if "xn--" in domain:
        indicators.append("Domain contains punycode that may disguise look-alike characters")
    if domain.count("-") >= 2:
        indicators.append("Domain contains multiple hyphens, which can indicate a deceptive look-alike")
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        indicators.append("URL uses an IP address instead of a recognizable domain")
    if len(domain) > 45:
        indicators.append("Unusually long domain name")
    return indicators


def _score_level(score: int) -> str:
    for floor, level in RISK_LEVELS:
        if score >= floor:
            return level
    return "Safe"


def analyze_event(payload: dict) -> dict:
    source = payload.get("source", "email").casefold()
    content = str(payload.get("content", "")).strip()
    url = str(payload.get("url", "")).strip()
    sender = str(payload.get("sender", "")).strip()
    combined = f"{content} {url} {sender}"
    indicators: list[str] = []
    recommendations: list[str] = []
    category = "Unclassified signal"
    score = 0

    if source == "network":
        requests = payload.get("requests_per_minute")
        request_baseline = payload.get("baseline_requests_per_minute")
        bytes_out = payload.get("bytes_out_mb")
        bytes_baseline = payload.get("baseline_bytes_out_mb")
        error_rate = payload.get("error_rate_percent")

        if requests is not None and request_baseline:
            ratio = requests / request_baseline
            if ratio >= 10:
                indicators.append(f"API request volume is {ratio:.1f}x its supplied baseline")
                score += 45
            elif ratio >= 3:
                indicators.append(f"API request volume is {ratio:.1f}x its supplied baseline")
                score += 30
            elif ratio >= 2:
                indicators.append(f"API request volume is {ratio:.1f}x its supplied baseline")
                score += 15

        if bytes_out is not None and bytes_baseline:
            ratio = bytes_out / bytes_baseline
            if ratio >= 10:
                indicators.append(f"Outbound data volume is {ratio:.1f}x its supplied baseline")
                score += 45
            elif ratio >= 3:
                indicators.append(f"Outbound data volume is {ratio:.1f}x its supplied baseline")
                score += 30
            elif ratio >= 2:
                indicators.append(f"Outbound data volume is {ratio:.1f}x its supplied baseline")
                score += 20

        if error_rate is not None:
            if error_rate >= 50:
                indicators.append(f"API error rate is unusually high at {error_rate:g}%")
                score += 20
            elif error_rate >= 25:
                indicators.append(f"API error rate is elevated at {error_rate:g}%")
                score += 10

        category = "Network / API anomaly"
        if indicators:
            recommendations.extend([
                "Review the affected service, client identity, and request logs",
                "Apply a temporary rate limit if the traffic is not authorized",
            ])
            if bytes_out is not None and bytes_baseline and bytes_out / bytes_baseline >= 3:
                recommendations.append("Review outbound data destinations and investigate possible exfiltration")
            if requests is not None and request_baseline and requests / request_baseline >= 3:
                recommendations.append("Validate the API client and rotate its credential if misuse is confirmed")
        else:
            indicators.append("Supplied measurements did not cross the configured anomaly thresholds")
            recommendations.append("Continue monitoring and compare against a representative baseline")
    elif source == "auth":
        failed = max(0, int(payload.get("failed_attempts") or 0))
        new_device = bool(payload.get("new_device"))
        unusual_location = bool(payload.get("unusual_location"))
        if failed >= 5:
            indicators.append(f"{failed} failed sign-in attempts exceed the 5-attempt review threshold")
            score += min(55, 25 + (failed - 5) * 3)
        if new_device:
            indicators.append("Sign-in originated from a device not previously seen for this user")
            score += 20
        if unusual_location:
            indicators.append("Sign-in location differs from the user's expected pattern")
            score += 20
        if indicators:
            category = "Account takeover"
            recommendations.extend(["Revoke active sessions", "Require MFA re-authentication"])
            if failed >= 5:
                recommendations.append("Rate-limit the source and review authentication logs")
        else:
            category = "Authentication activity"
            indicators.append("No configured abnormal sign-in indicators were supplied")
            recommendations.append("Continue monitoring sign-in activity")
    else:
        urgent = _matches(combined, URGENT_TERMS)
        credentials = _matches(combined, CREDENTIAL_TERMS)
        authorities = _matches(combined, AUTHORITY_TERMS)
        payment = _matches(combined, PAYMENT_TERMS)
        urls = _url_indicators(url)

        if urgent:
            indicators.append(f"Urgency language detected: {', '.join(urgent[:3])}")
            score += 20
        if credentials:
            indicators.append(f"Credential or account-verification language detected: {', '.join(credentials[:3])}")
            score += 30
        if authorities:
            indicators.append(f"Authority or organization reference detected: {', '.join(authorities[:3])}")
            score += 10
        if payment:
            indicators.append(f"Financial-action language detected: {', '.join(payment[:3])}")
            score += 20
        if urls:
            indicators.extend(urls)
            score += min(35, 15 * len(urls))
        if sender and re.search(r"@(gmail|outlook|yahoo|hotmail)\.", sender, re.IGNORECASE) and authorities:
            indicators.append("Authority-themed sender uses a consumer email provider")
            score += 20

        is_identity_report = source == "identity" or any(
            word in content.casefold() for word in ("voice note", "deepfake", "cloned voice", "video call", "impersonat")
        )
        if is_identity_report:
            category = "Impersonation / deepfake concern"
            if authorities:
                indicators.append("Message references an authority or trusted organization")
            if payment:
                indicators.append("Unverified request includes a financial action")
            if not indicators:
                indicators.append("Identity or media concern was reported; the media itself has not been analyzed")
            score = max(score, 25) + (20 if authorities else 0) + (20 if payment else 0)
            recommendations.extend(["Verify through a known, independent contact channel", "Pause sensitive actions until verified"])
            if any(word in content.casefold() for word in ("voice", "audio", "video", "deepfake", "cloned")):
                recommendations.append("Escalate media for human review; this prototype does not detect deepfakes")
        elif source == "url":
            category = "Malicious URL"
            if url and not urls:
                indicators.append("URL supplied for review; no configured structural warning was matched")
                score = max(score, 15)
            recommendations.extend(["Verify the destination domain before opening", "Check gateway logs for prior visits"])
        elif credentials and (urgent or authorities or url):
            category = "Credential phishing"
            recommendations.extend(["Quarantine the message", "Block or investigate the destination URL", "Warn the addressed user"])
        elif authorities and payment:
            category = "Digital impersonation"
            recommendations.extend(["Verify the sender using a known contact method", "Pause payment pending confirmation", "Report the impersonation to the security team"])
        elif indicators:
            category = "Suspicious message or URL"
            recommendations.extend(["Verify the sender out of band", "Review the destination URL before opening"])
        else:
            indicators.append("No configured phishing or impersonation indicators were matched")
            recommendations.append("Treat as unverified input, not proof of safety")
            score = 0

    score = min(100, max(0, score))
    severity = _score_level(score)
    if severity in ("Critical", "High"):
        recommendations.append("Escalate this event to the security analyst")
    if not recommendations:
        recommendations.append("Continue monitoring and verify context with the event owner")

    return {
        "id": f"CG-{uuid4().hex[:6].upper()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "source": str(payload.get("source", "email")).title(),
        "subject": (content.splitlines()[0][:88] if content else f"{category} signal") or f"{category} signal",
        "category": category,
        "severity": severity,
        "score": score,
        "status": "New",
        "summary": _explanation(category, severity, indicators),
        "indicators": indicators,
        "recommendations": list(dict.fromkeys(recommendations)),
    }


def _explanation(category: str, severity: str, indicators: list[str]) -> str:
    if severity == "Safe":
        return f"No configured risk signals matched this {category.lower()} input. This is not a guarantee that it is safe."
    lead = ", ".join(indicators[:2]).lower()
    return f"{severity} {category.lower()} assessment based on {lead}. This is a prototype heuristic, not a confirmed incident."
