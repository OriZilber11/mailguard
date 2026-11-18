from tldextract import TLDExtract

# suffix_list_urls=() -> never touches the network; uses the list bundled with the package.
_extract = TLDExtract(suffix_list_urls=())


def registrable_domain(host: str) -> str:
    """'mail.news.example.co.uk' -> 'example.co.uk'. Falls back to the host itself."""
    host = host.strip().lower().rstrip(".")
    return _extract(host).top_domain_under_public_suffix or host


def has_public_suffix(host: str) -> bool:
    """True for real domains like 'example.com'; False for 'file.pdf' or '3.5'."""
    return bool(_extract(host.strip().lower()).suffix)
