"""域名与地址判定工具。

负责：内部/外部地址判定、域名提取、仿冒（lookalike）域名识别。
全部使用字符串运算，无第三方依赖。
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

# 常见一次性/免费邮箱域名（攻击者常用作外部落点，且不属于任何企业合作方）
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.jp", "icloud.com", "me.com", "mail.com",
    "proton.me", "protonmail.com", "gmx.com", "aol.com", "zoho.com",
    "qq.com", "163.com", "126.com", "sina.com", "foxmail.com",
}

# 西里尔/希腊等字符到形似拉丁字符的常见映射（同形异义 homoglyph）
_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ε": "e", "ι": "i", "υ": "u", "ρ": "p",
    "κ": "k", "ν": "v", "χ": "x", "γ": "y",
}

_EMAIL_RE = re.compile(r"[^@\s<>;,]+@([^@\s<>;,]+\.[^@\s<>;,]+)")


def normalize_domain(value: str) -> str:
    """提取并归一化域名：小写、去端口、去 URL 前缀、去尾部点。"""
    if not value:
        return ""
    value = value.strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split(":")[0].rstrip(".")
    # 国际化域名可能是 Punycode，保持原样比较；非 ASCII 单独走同形检测
    return value


def extract_email_addresses(values: list[str]) -> list[str]:
    """从一批可能是地址/联系人字符串的值里提取邮箱地址。"""
    found: list[str] = []
    for value in values or []:
        if not value:
            continue
        for match in _EMAIL_RE.finditer(str(value)):
            found.append(match.group(0).lower())
    return found


def domain_of(address: str) -> str:
    return normalize_domain(address)


def is_internal_address(address: str, internal_domains: set[str]) -> bool:
    domain = normalize_domain(address)
    if not domain:
        return False
    internal = {normalize_domain(item) for item in internal_domains}
    if domain in internal:
        return True
    # 子域也算内部，例如 mail.contoso.com 对 contoso.com
    return any(domain.endswith("." + item) for item in internal if item)


def external_targets(addresses: list[str], internal_domains: set[str]) -> list[str]:
    result = []
    for address in addresses:
        normalized = address.strip().lower()
        if normalized and not is_internal_address(normalized, internal_domains):
            result.append(normalized)
    return result


def is_free_mail(address: str) -> bool:
    return normalize_domain(address) in FREE_MAIL_DOMAINS


def _skeleton(domain: str) -> str:
    """把同形字符折叠成拉丁骨架，用于 homoglyph 比较。"""
    chars = []
    for char in domain:
        if char in _HOMOGLYPH_MAP:
            chars.append(_HOMOGLYPH_MAP[char])
        else:
            chars.append(char)
    return "".join(chars)


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_left != char_right),
            ))
        previous = current
    return previous[-1]


def lookalike_of_internal(address: str, internal_domains: set[str]) -> Optional[dict]:
    """判断外部地址域名是否仿冒内部域名。

    返回 {"domain", "matched_internal", "reasons": [...]} 或 None。
    检测手段：同形异义字符、编辑距离 1~2、插入连字符、多余前缀/后缀。
    """
    domain = normalize_domain(address)
    if not domain or is_internal_address(address, internal_domains):
        return None

    skeleton = _skeleton(domain)
    ascii_only = all(ord(char) < 128 for char in domain)
    for internal in sorted({normalize_domain(item) for item in internal_domains if item}):
        reasons: list[str] = []
        if not ascii_only and skeleton == internal:
            reasons.append("同形异义字符(homoglyph)，折叠后与内部域名一致")
        elif not ascii_only and _levenshtein(skeleton, internal) <= 2:
            reasons.append("含非ASCII字符且骨架与内部域名高度相似")

        base_distance = _levenshtein(domain, internal)
        if ascii_only and 1 <= base_distance <= 2:
            reasons.append(f"与内部域名 {internal} 编辑距离={base_distance}")

        stripped_hyphen = domain.replace("-", "")
        if ascii_only and stripped_hyphen == internal and "-" in domain:
            reasons.append("仅通过插入连字符仿冒内部域名")

        # contoso.com.evil.net 这类子域包裹：内部域名完整出现在外部域名的前缀位置，
        # 但真正的注册域（最后两段）是外部实体
        registered = ".".join(domain.split(".")[-2:])
        if domain != internal and registered != internal and (
            domain.startswith(internal + ".") or ("." + internal + ".") in domain
        ):
            reasons.append("内部域名出现在子域前缀位置（注册者实际为外部域名）")

        if reasons:
            return {"domain": domain, "matched_internal": internal, "reasons": reasons}
    return None
