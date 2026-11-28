# Copyright (c) 2026 EazyWhale (https://github.com/lonion-1)
# SPDX-License-Identifier: MIT
"""Pembaca & validator konfigurasi TOML modular (indexer.toml + legal_profiles.toml + categories/*.toml).
Mendukung tomllib, tomli, serta fallback parser TOML murni tanpa dependensi eksternal.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib as _toml_mod
except ModuleNotFoundError:
    try:
        import tomli as _toml_mod  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml_mod = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]

_RE_INLINE_GLOBAL_FLAG = re.compile(r"(?<!\\)(?:\\\\)*\(\?([aiLmsux]+)\)")


class ConfigError(Exception):
    """Kesalahan struktur atau isi file konfigurasi TOML."""


def _strip_toml_comment(line: str) -> str:
    in_sq = False
    in_dq = False
    esc = False
    out: list[str] = []
    for ch in line:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\" and in_dq:
            out.append(ch)
            esc = True
            continue
        if ch == '"' and not in_sq:
            in_dq = not in_dq
            out.append(ch)
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            out.append(ch)
            continue
        if ch == "#" and not in_sq and not in_dq:
            break
        out.append(ch)
    return "".join(out).strip()


def _parse_toml_scalar(val: str):
    v = val.strip()
    if v == "true":
        return True
    if v == "false":
        return False
    if (v.startswith('"') and v.endswith('"')) or (
        v.startswith("'") and v.endswith("'")
    ):
        return ast.literal_eval(v)
    if re.fullmatch(r"[+-]?\d+", v):
        return int(v)
    if re.fullmatch(r"[+-]?\d+\.\d+", v):
        return float(v)
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        items = []
        buf: list[str] = []
        in_sq = False
        in_dq = False
        esc = False
        for ch in inner:
            if esc:
                buf.append(ch)
                esc = False
                continue
            if ch == "\\" and in_dq:
                buf.append(ch)
                esc = True
                continue
            if ch == '"' and not in_sq:
                in_dq = not in_dq
                buf.append(ch)
                continue
            if ch == "'" and not in_dq:
                in_sq = not in_sq
                buf.append(ch)
                continue
            if ch == "," and not in_sq and not in_dq:
                tok = "".join(buf).strip()
                if tok:
                    items.append(_parse_toml_scalar(tok))
                buf = []
                continue
            buf.append(ch)
        last_tok = "".join(buf).strip()
        if last_tok:
            items.append(_parse_toml_scalar(last_tok))
        return items
    raise ConfigError(f"Nilai TOML tidak dikenali: {val!r}")


def _parse_toml_fallback(raw_text: str) -> dict:
    root: dict = {}
    cur = root
    lines = raw_text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_toml_comment(lines[i])
        i += 1
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            sec_path = [
                p.strip().strip('"').strip("'")
                for p in line[1:-1].split(".")
                if p.strip()
            ]
            cur = root
            for part in sec_path:
                cur = cur.setdefault(part, {})
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().strip('"').strip("'")
        val = val.strip()
        if val.startswith("[") and not val.endswith("]"):
            chunks = [val]
            while i < len(lines):
                nxt = _strip_toml_comment(lines[i])
                i += 1
                if nxt:
                    chunks.append(nxt)
                    if nxt.endswith("]"):
                        break
            val = " ".join(chunks)
        cur[key] = _parse_toml_scalar(val)
    return root


def _compile_literals(
    words: list[str], word_boundary: bool = True
) -> re.Pattern | None:
    cleaned = [re.escape(w.strip().lower()) for w in (words or []) if w and w.strip()]
    if not cleaned:
        return None
    joined = "|".join(sorted(set(cleaned), key=len, reverse=True))
    pat = f"(?<!\\w)(?:{joined})(?!\\w)" if word_boundary else f"(?:{joined})"
    return re.compile(pat, re.IGNORECASE)


def _normalize_subpattern(pat: str) -> tuple[str, list[str]]:
    """Tarik global flag (?i), (?m), (?s), dll. dari dalam sub-pola agar aman saat dibungkus (?:...)."""
    found: list[str] = []

    def _repl(m: re.Match) -> str:
        full = m.group(0)
        flag_chars = m.group(1)
        prefix_bs = full[: full.index("(?")]
        for ch in flag_chars:
            if ch not in found:
                found.append(ch)
        return prefix_bs

    stripped = _RE_INLINE_GLOBAL_FLAG.sub(_repl, pat)
    return stripped, found


def _compile_regexes(patterns: list[str], label: str) -> re.Pattern | None:
    raw_cleaned = [p.strip() for p in (patterns or []) if p and p.strip()]
    if not raw_cleaned:
        return None

    normalized_parts: list[str] = []
    extra_flags: list[str] = []
    for p in raw_cleaned:
        norm_p, flags = _normalize_subpattern(p)
        normalized_parts.append(norm_p)
        for f in flags:
            if f != "i" and f not in extra_flags:
                extra_flags.append(f)

    lead = f"(?{''.join(extra_flags)})" if extra_flags else ""
    try:
        return re.compile(
            lead + "(?:(?:" + ")|(?:".join(normalized_parts) + "))", re.IGNORECASE
        )
    except re.error as e:
        raise ConfigError(f"Regex tidak valid di {label}: {e}") from e


@dataclass
class LegalProfileRule:
    name: str
    label: str
    weight: int
    official_domains: frozenset[str]
    nav_paths: tuple[str, ...]
    re_body_markers: re.Pattern | None


@dataclass
class LegalConfig:
    institutional_tlds: tuple[str, ...]
    jsonld_benign_types: frozenset[str]
    authority_domains: frozenset[str]
    re_news_reporting: re.Pattern | None
    identity_paths: tuple[str, ...]
    re_action_path: re.Pattern | None
    profiles: dict[str, LegalProfileRule] = field(default_factory=dict)


@dataclass
class CategoryRule:
    name: str
    label: str
    enabled: bool
    min_pillars: int
    min_illegal_score: int
    veto_legal_threshold: int
    queries_cfg: dict
    re_domain_hints: re.Pattern | None
    high_risk_tlds: tuple[str, ...]
    re_mirror_patterns: re.Pattern | None
    re_active_intent: re.Pattern | None
    re_passive_context: re.Pattern | None
    re_url_paths: re.Pattern | None
    re_dom_signatures: re.Pattern | None
    re_ad_markers: re.Pattern | None
    outbound_ratio_threshold: float
    re_suspect_outbound: re.Pattern | None


@dataclass
class IndexerConfig:
    run: dict
    engines: dict
    multi_tlds: frozenset[str]
    allowlist: frozenset[str]
    shorteners: frozenset[str]
    parked_hints: tuple[str, ...]
    mirror_templates: tuple[str, ...]
    legal: LegalConfig
    categories: dict[str, CategoryRule]
    re_any_illegal_domain: re.Pattern | None


def _load_toml(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"File konfigurasi wajib tidak ditemukan: {path}")
    try:
        if _toml_mod is not None:
            with path.open("rb") as f:
                return _toml_mod.load(f)
        return _parse_toml_fallback(path.read_text(encoding="utf-8"))
    except ConfigError:
        raise
    except Exception as e:
        raise ConfigError(f"Format TOML rusak di {path}: {e}") from e


def _load_external_engines_config(cdir: Path) -> dict:
    """Muat konfigurasi mesin pencari dari repo privat EazyVault (jika tersedia)."""
    candidates: list[Path] = []
    env_file = os.environ.get("EAZYVAULT_ENGINES_TOML", "").strip()
    if env_file:
        candidates.append(Path(env_file).expanduser())
    env_dir = os.environ.get("EAZYVAULT_DIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir).expanduser() / "config" / "engines.toml")

    candidates.extend(
        [
            ROOT.parent / "EazyVault" / "config" / "engines.toml",
            ROOT / "EazyVault" / "config" / "engines.toml",
            cdir / "engines.toml",
        ]
    )

    for path in candidates:
        if path.is_file():
            raw = _load_toml(path)
            eng_sec = raw.get("engines")
            if isinstance(eng_sec, dict):
                return dict(eng_sec)
            return dict(raw)
    return {}


def load_indexer_config(config_dir: Path | None = None) -> IndexerConfig:
    cdir = config_dir or (ROOT / "config")
    main_raw = _load_toml(cdir / "indexer.toml")
    legal_raw = _load_toml(cdir / "legal_profiles.toml")

    run_cfg = dict(main_raw.get("run") or {})
    eng_cfg = dict(main_raw.get("engines") or {})
    ext_eng_cfg = _load_external_engines_config(cdir)
    if ext_eng_cfg:
        eng_cfg.update(ext_eng_cfg)
    dom_cfg = dict(main_raw.get("domain_rules") or {})

    multi_tlds = frozenset(
        x.strip().lower().lstrip(".")
        for x in dom_cfg.get("multi_tlds", [])
        if x.strip()
    )
    allowlist = frozenset(
        x.strip().lower().removeprefix("www.")
        for x in dom_cfg.get("allowlist_domains", [])
        if x.strip()
    )
    shorteners = frozenset(
        x.strip().lower().removeprefix("www.")
        for x in dom_cfg.get("shorteners", [])
        if x.strip()
    )
    parked_hints = tuple(
        x.strip().lower() for x in dom_cfg.get("parked_hints", []) if x.strip()
    )
    mirror_templates = tuple(
        x.strip() for x in dom_cfg.get("mirror_templates", []) if x.strip()
    )

    gen_legal = legal_raw.get("general") or {}
    inst_tlds = tuple(
        x.strip().lower() for x in gen_legal.get("institutional_tlds", []) if x.strip()
    )
    jsonld_types = frozenset(
        x.strip() for x in gen_legal.get("jsonld_benign_types", []) if x.strip()
    )
    auth_doms = frozenset(
        x.strip().lower() for x in gen_legal.get("authority_domains", []) if x.strip()
    )
    re_news = _compile_literals(
        gen_legal.get("news_reporting_markers", []), word_boundary=False
    )

    probes = legal_raw.get("adaptive_probes") or {}
    id_paths = tuple(
        x.strip().lower() for x in probes.get("identity_paths", []) if x.strip()
    )
    action_rx_raw = str(probes.get("action_path_regex", "")).strip()
    re_action_path = (
        _compile_regexes([action_rx_raw], "legal_profiles.adaptive_probes")
        if action_rx_raw
        else None
    )

    profiles: dict[str, LegalProfileRule] = {}
    for pname, pdata in (legal_raw.get("profiles") or {}).items():
        if not isinstance(pdata, dict):
            continue
        profiles[pname] = LegalProfileRule(
            name=pname,
            label=str(pdata.get("label", pname)),
            weight=int(pdata.get("weight", 3)),
            official_domains=frozenset(
                x.strip().lower().removeprefix("www.")
                for x in pdata.get("official_domains", [])
                if x.strip()
            ),
            nav_paths=tuple(
                x.strip().lower() for x in pdata.get("nav_paths", []) if x.strip()
            ),
            re_body_markers=_compile_literals(
                pdata.get("body_markers", []), word_boundary=False
            ),
        )

    legal_cfg = LegalConfig(
        institutional_tlds=inst_tlds,
        jsonld_benign_types=jsonld_types,
        authority_domains=auth_doms,
        re_news_reporting=re_news,
        identity_paths=id_paths,
        re_action_path=re_action_path,
        profiles=profiles,
    )

    cat_dir = cdir / "categories"
    if not cat_dir.exists():
        raise ConfigError(f"Direktori kategori tidak ditemukan: {cat_dir}")

    categories: dict[str, CategoryRule] = {}
    all_domain_hints: list[str] = []

    for toml_path in sorted(cat_dir.glob("*.toml")):
        cdata = _load_toml(toml_path)
        cname = toml_path.stem.strip().lower()
        meta = cdata.get("meta") or {}
        if not bool(meta.get("enabled", True)):
            continue

        p_dom = cdata.get("pillar_domain") or {}
        p_sem = cdata.get("pillar_semantics") or {}
        p_ana = cdata.get("pillar_anatomy") or {}
        p_eco = cdata.get("pillar_ecosystem") or {}

        hints = [x.strip().lower() for x in p_dom.get("domain_hints", []) if x.strip()]
        all_domain_hints.extend(hints)

        categories[cname] = CategoryRule(
            name=cname,
            label=str(meta.get("label", cname)),
            enabled=True,
            min_pillars=int(meta.get("min_pillars", 3)),
            min_illegal_score=int(meta.get("min_illegal_score", 8)),
            veto_legal_threshold=int(meta.get("veto_legal_threshold", 5)),
            queries_cfg=dict(cdata.get("queries") or {}),
            re_domain_hints=_compile_literals(hints, word_boundary=False),
            high_risk_tlds=tuple(
                x.strip().lower() for x in p_dom.get("high_risk_tlds", []) if x.strip()
            ),
            re_mirror_patterns=_compile_regexes(
                p_dom.get("mirror_patterns", []), f"{cname}.mirror_patterns"
            ),
            re_active_intent=_compile_literals(
                p_sem.get("active_intent", []), word_boundary=False
            ),
            re_passive_context=_compile_literals(
                p_sem.get("passive_context", []), word_boundary=False
            ),
            re_url_paths=_compile_regexes(
                p_ana.get("url_path_patterns", []), f"{cname}.url_path_patterns"
            ),
            re_dom_signatures=_compile_literals(
                p_ana.get("dom_signatures", []), word_boundary=False
            ),
            re_ad_markers=_compile_literals(
                p_ana.get("ad_network_markers", []), word_boundary=False
            ),
            outbound_ratio_threshold=float(p_eco.get("outbound_ratio_threshold", 0.25)),
            re_suspect_outbound=_compile_literals(
                p_eco.get("suspect_outbound_hints", []), word_boundary=False
            ),
        )

    if not categories:
        raise ConfigError("Tidak ada kategori aktif di config/categories/*.toml")

    re_any_dom = _compile_literals(all_domain_hints, word_boundary=False)
    return IndexerConfig(
        run=run_cfg,
        engines=eng_cfg,
        multi_tlds=multi_tlds,
        allowlist=allowlist,
        shorteners=shorteners,
        parked_hints=parked_hints,
        mirror_templates=mirror_templates,
        legal=legal_cfg,
        categories=categories,
        re_any_illegal_domain=re_any_dom,
    )
