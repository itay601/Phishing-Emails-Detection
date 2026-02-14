import logging
import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class LinkInfo:
    href: str
    display_text: str
    is_mismatched: bool = False


@dataclass
class ParsedEmail:
    sender: str = ""
    sender_name: str = ""
    recipient: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict = field(default_factory=dict)
    links: list[LinkInfo] = field(default_factory=list)


URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def parse_email(email_data: dict) -> ParsedEmail:
    """Parse raw email data dict into a structured ParsedEmail."""
    logger.debug("Parsing email from '%s'", email_data.get("from", "(unknown)"))

    body_html = email_data.get("body_html", "")
    body_text = email_data.get("body_text", "")

    # Extract links from HTML first
    links = extract_links(body_html)
    html_hrefs = {link.href.lower() for link in links}

    # Also extract plain-text URLs not already found in HTML
    for match in URL_REGEX.finditer(body_text):
        url = match.group().rstrip(".,;:!?)")
        if url.lower() not in html_hrefs:
            links.append(LinkInfo(href=url, display_text=url, is_mismatched=False))
            html_hrefs.add(url.lower())

    mismatched = [l for l in links if l.is_mismatched]
    if mismatched:
        logger.warning("Found %d mismatched link(s) in email", len(mismatched))
        for l in mismatched:
            logger.warning("  Mismatch: display='%s' → href='%s'", l.display_text, l.href)

    logger.debug(
        "Parse complete — %d link(s), subject: '%s'",
        len(links),
        email_data.get("subject", ""),
    )

    return ParsedEmail(
        sender=email_data.get("from", ""),
        sender_name=email_data.get("from_name", ""),
        recipient=email_data.get("to", ""),
        subject=email_data.get("subject", ""),
        body_text=body_text,
        body_html=body_html,
        headers=email_data.get("headers", {}),
        links=links,
    )


def extract_links(html: str) -> list[LinkInfo]:
    """Extract all links from HTML body, detecting display/href mismatches."""
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    links = []

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        display_text = anchor.get_text(strip=True)
        is_mismatched = _check_link_mismatch(href, display_text)
        links.append(LinkInfo(href=href, display_text=display_text, is_mismatched=is_mismatched))

    return links


def _check_link_mismatch(href: str, display_text: str) -> bool:
    """Check if display text looks like a URL that doesn't match the href."""
    url_pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
    if not url_pattern.match(display_text):
        return False

    # Both look like URLs — compare domains
    href_domain = _extract_domain(href)
    display_domain = _extract_domain(display_text)

    if href_domain and display_domain:
        return href_domain.lower() != display_domain.lower()
    return False


def _extract_domain(url: str) -> str | None:
    """Extract domain from a URL string."""
    match = re.search(r"https?://([^/:\s]+)", url, re.IGNORECASE)
    return match.group(1) if match else None
