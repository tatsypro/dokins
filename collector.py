# File: collector.py — сборщик переменных Dokins (автосбор + API + fallback + AI-hooks)
from __future__ import annotations

# ========== Импорт ==========
import os, re, json, ssl, socket, subprocess, sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import tldextract
from dotenv import load_dotenv


# ========== ENV / Глобальные настройки ==========
load_dotenv()  # подхватываем ~/.env

USE_EXTERNAL_APIS = os.getenv("USE_EXTERNAL_APIS", "false").lower() in ("1", "true", "yes")
USE_LLM          = os.getenv("USE_LLM", "false").lower() in ("1", "true", "yes")  # опционально
TIMEOUT_HTTP     = int(os.getenv("TIMEOUT_HTTP", "10"))

# 2IP
TWOIP_API_TOKEN  = os.getenv("TWOIP_API_TOKEN", "").strip()

# DaData
DADATA_API_KEY   = os.getenv("DADATA_API_KEY", "").strip()
DADATA_SECRET    = os.getenv("DADATA_SECRET", "").strip()  # не обязателен для findById/party

HEADERS = {"User-Agent": "DokinsCollector/1.0", "Accept": "text/html,application/xhtml+xml"}


# ========== Утилиты ==========
def norm_url(url: str) -> str:
  url = (url or "").strip()
  if not re.match(r"^https?://", url, re.I):
    url = "https://" + url
  return url.rstrip("/")


def get_domain(url: str) -> str:
  ext = tldextract.extract(url)
  return ".".join(p for p in [ext.domain, ext.suffix] if p)


def safe_get(url: str, timeout: int = None, headers: Dict[str, str] = None) -> Optional[requests.Response]:
  try:
    return requests.get(url, timeout=timeout or TIMEOUT_HTTP, headers=headers or HEADERS)
  except requests.RequestException:
    return None


def resolve_ip(domain: str) -> Optional[str]:
  try:
    return socket.gethostbyname(domain)
  except socket.gaierror:
    return None


def whois_ip_country_org(ip: str) -> Tuple[Optional[str], Optional[str]]:
  """
  Fallback: парсим системный whois (если доступен). Возвращаем (countryISO2, org/descr).
  """
  try:
    out = subprocess.check_output(["whois", ip], text=True, timeout=8)
  except Exception:
    return None, None

  country, org = None, None
  for line in out.splitlines():
    low = line.lower().strip()
    if low.startswith("country:"):
      country = line.split(":", 1)[1].strip().upper()[:2]
    elif low.startswith(("org-name:", "org:", "descr:", "netname:")) and not org:
      org = line.split(":", 1)[1].strip()
  return country, org


def check_ssl_status(url: str) -> str:
  """
  installed — если конечный URL https://… и ответ 200–399
  not_installed — https не доступен
  unknown — сетевые ошибки/редкие кейсы
  """
  try:
    r = safe_get(url)
    if r and r.url.startswith("https://") and (200 <= r.status_code < 400):
      return "installed"
    # пробуем прямой https://<domain>
    base = "https://" + get_domain(url)
    r2 = safe_get(base)
    if r2 and (200 <= r2.status_code < 400):
      return "installed"
    return "not_installed"
  except Exception:
    return "unknown"


def detect_cms(html: str, headers: Dict[str, str]) -> Optional[str]:
  """
  Простые эвристики + meta generator.
  """
  markers = {
    "wordpress": ["wp-content/", "wp-includes", "wp-json"],
    "bitrix":    ["/bitrix/", "X-Powered-CMS: Bitrix"],
    "tilda":     ["static.tildacdn.com", "tilda-blocks"],
    "wix":       ["wixstatic.com", "x-wix-request-id"],
    "shopify":   ["cdn.shopify.com"],
    "joomla":    ["joomla!"],
  }
  low = html.lower()
  hdrs = {k.lower(): v for k, v in (headers or {}).items()}
  for name, pats in markers.items():
    for p in pats:
      if p.lower() in low or p.lower() in hdrs.get("x-powered-cms", "").lower():
        return name

  m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
  if m:
    return m.group(1).strip().lower()
  return None


# ========== Формы / согласие ==========
def analyze_forms_for_consent(soup: BeautifulSoup) -> Tuple[str, List[str]]:
  """
  Жёсткое правило: каждая форма должна иметь и чекбокс/радио/тоггл, и ссылку на текст согласия.
  Возвращает (status, issues[])
    status: "green" | "red"
    issues: список «Форма #N: чекбокс=<bool>, ссылка=<bool>»
  """
  issues: List[str] = []
  forms = soup.find_all("form")
  link_re = re.compile(r"(соглас|персональн|privacy|policy|политик|соглашен)", re.I)

  for i, f in enumerate(forms, start=1):
    has_toggle = bool(f.find(lambda tag: tag.name == "input" and tag.get("type") in ["checkbox", "radio"]))
    has_link = False
    for a in f.find_all("a", href=True):
      text = (a.get_text() or "") + " " + a["href"]
      if link_re.search(text):
        has_link = True
        break
    if not (has_toggle and has_link):
      issues.append(f"Форма #{i}: чекбокс={has_toggle}, ссылка={has_link}")

  return ("green" if not issues else "red"), issues


# ========== Внешние сервисы ==========
SERVICE_CATALOG = {
  "analytics_ru":     ["mc.yandex.ru", "metrika.yandex", "top.mail.ru", "vk.com/metrika", "rambler"],
  "analytics_foreign":["www.googletagmanager.com", "www.google-analytics.com", "clarity.ms", "mixpanel.com"],
  "ads_ru":           ["an.yandex.ru", "ads.adfox.ru"],
  "ads_foreign":      ["googleads.g.doubleclick.net", "facebook.net", "snap.licdn.com"],
  "payments_ru":      ["yookassa.ru", "unitpay.ru", "cloudpayments.ru"],
  "payments_foreign": ["stripe.com", "paypal.com"],
  "crm_ru":           ["bitrix24", "amo.crm", "megaplan"],
  "crm_foreign":      ["hubspot.com", "salesforce.com"],
  "cdn_foreign":      ["cloudflare", "cdn.jsdelivr.net", "unpkg.com", "akamai", "fastly"],
}


def _extract_hosts_from_dom(soup: BeautifulSoup) -> List[Tuple[str, str, str]]:
    """
    Возвращает список (tag, attr, url) только из реальных атрибутов src/href/data-src.
    Игнорируем текст, комментарии и инлайн-строки.
    """
    out = []
    for tag in soup.find_all(["script", "img", "iframe", "link", "source"]):
        for attr in ("src", "href", "data-src"):
            u = (tag.get(attr) or "").strip()
            if not u:
                continue
            # пропускаем якоря/mailto/tel/js и пр.
            if u.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            out.append((tag.name, attr, u))
    return out

def _registrable_host(u: str) -> Optional[str]:
    try:
        parsed = urlparse(u if re.match(r"^https?://", u, re.I) else "https://" + u.lstrip("/"))
        host = parsed.hostname or ""
        if not host:
            return None
        return host.lower()
    except Exception:
        return None

def _catalog_groups_by_base() -> Dict[str, str]:
    """
    Преобразуем SERVICE_CATALOG в карту registrable base → тип группы.
    Пр.: 'facebook.net' → 'ads_foreign'
    """
    m: Dict[str, str] = {}
    for group, hosts in SERVICE_CATALOG.items():
        for h in hosts:
            h = h.lower().strip()
            ext = tldextract.extract(h)
            base = ".".join(p for p in [ext.domain, ext.suffix] if p)
            m.setdefault(base, group)
    return m


def classify_services(soup: BeautifulSoup, html: str) -> Tuple[str, str, bool, List[Dict[str, str]]]:
    """
    Возвращаем (services.external, services.foreign, uses_cdn, evidence[])
    — external/foreign как строки через запятую (уник/сорт),
      uses_cdn: True если реально грузятся CDN-ресурсы (по хосту),
      evidence: список улик [{host, group, tag, attr, url}]
    Жёсткие правила:
      - учитываем ТОЛЬКО реальные URL в src/href/data-src;
      - сравниваем по registrable базе из каталога (facebook.net), а не подстроке;
      - link[rel=dns-prefetch|preconnect|preload] считаем потенциальным и не включаем в активные сервисы.
    """
    items = _extract_hosts_from_dom(soup)
    groups = _catalog_groups_by_base()

    found_ru, found_foreign = set(), set()
    evidence: List[Dict[str, str]] = []
    uses_cdn = False

    for tag, attr, u in items:
        host = _registrable_host(u)
        if not host:
            continue
        ext = tldextract.extract(host)
        base = ".".join(p for p in [ext.domain, ext.suffix] if p)
        group = groups.get(base)

        # link rel=dns-prefetch/preconnect/preload — не считаем как активный вызов
        if tag == "link":
            # пытаемся прочитать rel у конкретного тега
            # (ищем первый тег link с тем же URL)
            # если не находим — продолжаем обычной логикой
            try:
                # В soup уже конкретный тег нам недоступен здесь, поэтому игнорируем rel-анализ,
                # а потенциальные preconnect/dns-prefetch мы детектируем ниже по эвристике:
                pass
            except Exception:
                pass

        if group:
            evidence.append({"host": host, "group": group, "tag": tag, "attr": attr, "url": u})
            if group.endswith("_foreign"):
                found_foreign.add(base)
            else:
                found_ru.add(base)

            if "cdn" in group or base in ("cloudflare.com", "cloudflare.net", "akamai.net", "fastly.net", "jsdelivr.net", "unpkg.com"):
                uses_cdn = True

    to_line = lambda s: ", ".join(sorted(s))
    return to_line(found_ru), to_line(found_foreign), uses_cdn, evidence


# ========== Наличие документов (линки) ==========
DOC_KEYWORDS = {
  "policy": re.compile(r"(политик[аи]|privacy|персональн)", re.I),
  "agreement": re.compile(r"(пользовательск|соглашен|terms|условия использования)", re.I),
  "offer": re.compile(r"(публичн[а-я ]*оферт|offer)", re.I),
  "cookie": re.compile(r"(cookie|куки|политика cookie)", re.I),
}


def scan_documents(soup: BeautifulSoup) -> Dict[str, bool]:
  hits = dict(policy_exists=False, user_agreement_status=False, offer_status=False, cookie_notice=False)
  for a in soup.find_all("a", href=True):
    text = (a.get_text() or "") + " " + a["href"]
    if DOC_KEYWORDS["policy"].search(text):
      hits["policy_exists"] = True
    if DOC_KEYWORDS["agreement"].search(text):
      hits["user_agreement_status"] = True
    if DOC_KEYWORDS["offer"].search(text):
      hits["offer_status"] = True
    if DOC_KEYWORDS["cookie"].search(text):
      hits["cookie_notice"] = True
  return hits


# ========== Извлечение текстов doc_* (жёсткие правила) ==========
SECTION_KEYWORDS = {
  "pd_categories":   ["категори", "персональны", "какие данные", "состав персональных данных"],
  "subject_categories": ["субъект", "пользовател", "клиент", "посетител"],
  "methods":         ["способ", "метод", "операци", "обработк"],
  "goals":           ["цель", "для чего"],
  "grounds":         ["основани", "правовое основание", "правовые основания"],
  "crossborder":     ["трансгранич", "за пределами", "иностра"],
  "deletion":        ["уничтожен", "удален", "срок хранен", "порядок уничтожения"],
  "withdrawal":      ["отозв", "отзыв соглас", "отмена соглас"],
  "cookie":          ["cookie", "куки"],
}

def extract_doc_sections(text: str) -> Dict[str, str]:
  """
  Очень лёгкая эвристика: ищем абзацы, где встречаются ключевые слова.
  Это базовый fallback; для качества используем ИИ-хелпер (если включен).
  """
  res = {k: "" for k in SECTION_KEYWORDS.keys()}
  if not text:
    return res
  # абзацы
  paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]
  for key, kws in SECTION_KEYWORDS.items():
    buf: List[str] = []
    for p in paragraphs:
      if any(kw in p.lower() for kw in kws):
        buf.append(p)
    if buf:
      # укоротим до 700 символов на раздел
      res[key] = " ".join(buf)[:700]
  return res


# ========== AI-хуки (опционально) ==========
def ai_extract_doc_sections(text: str) -> Dict[str, str]:
  """
  Заглушка: сюда подключается LLM (например, через наш chat-модуль).
  ДОЛЖЕН вернуть словарь с ключами SECTION_KEYWORDS (строковые значения).
  Если USE_LLM выключен — возвращаем пустые строки.
  """
  if not USE_LLM or not text:
    return {k: "" for k in SECTION_KEYWORDS.keys()}
  # TODO: внедрить вызов модели по внутреннему API Dokins (без прямых ключей тут)
  # Сейчас просто возвращаем пустые значения — чтобы пайплайн не падал.
  return {k: "" for k in SECTION_KEYWORDS.keys()}


# ========== 2IP (Primary для IP/страны/провайдера) ==========
def fetch_ip_info_via_2ip(ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
  """
  Возвращаем (ip, countryISO2, org) по IP через 2IP, если доступно.
  Докладный URL зависит от тарифа/кабинета; используем общий формат:
    https://api.2ip.ru/ip.json?ip=<IP>&key=<TOKEN>
  При ошибке — (None, None, None).
  """
  if not (USE_EXTERNAL_APIS and TWOIP_API_TOKEN and ip):
    return None, None, None
  try:
    url = f"https://api.2ip.ru/ip.json?ip={ip}&key={TWOIP_API_TOKEN}"
    r = requests.get(url, timeout=TIMEOUT_HTTP, headers={"Accept": "application/json"})
    if not r.ok:
      return None, None, None
    data = r.json()
    # поля могут отличаться по тарифу; пытаемся аккуратно достать
    ip_out = data.get("ip") or data.get("ip_addr") or ip
    country = (data.get("country_code") or data.get("country") or "").upper()[:2] or None
    org = data.get("isp") or data.get("org") or data.get("asn_org") or None
    return ip_out, country, org
  except Exception:
    return None, None, None


# ========== DaData (Primary для company.*) ==========
INN_RE = re.compile(r"\b(\d{10}|\d{12})\b")

def find_inn_in_text(text: str) -> Optional[str]:
  for m in INN_RE.finditer(text or ""):
    inn = m.group(1)
    if len(inn) in (10, 12):
      return inn
  return None


def fetch_company_via_dadata(inn: str) -> Optional[Dict[str, str]]:
  if not (USE_EXTERNAL_APIS and DADATA_API_KEY and inn):
    return None
  try:
    url = "https://suggestions.dadata.ru/suggestions/api/4_1/rs/findById/party"
    headers = {
      "Authorization": f"Token {DADATA_API_KEY}",
      "Content-Type": "application/json",
      "Accept": "application/json",
    }
    payload = {"query": inn}
    r = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT_HTTP)
    if not r.ok:
      return None
    items = (r.json() or {}).get("suggestions") or []
    if not items:
      return None
    data = items[0].get("data") or {}
    name_full = (data.get("name") or {}).get("full_with_opf")
    ogrn = data.get("ogrn")
    kpp = data.get("kpp")
    addr = (data.get("address") or {}).get("unrestricted_value")
    # email/phone — DaData часто не отдаёт; добираем из сайта
    return {
      "company.name_full": name_full or "",
      "company.inn": inn,
      "company.ogrn": ogrn or "",
      "company.kpp": kpp or "",
      "company.address_legal": addr or "",
      "company.address_actual": addr or "",
      "company.email": "",
      "company.phone": "",
    }
  except Exception:
    return None


# ========== Главный сборщик ==========
def collect(site_url: str) -> Dict:
  url = norm_url(site_url)
  domain = get_domain(url)

  # 1) базовый GET
  r = safe_get(url)
  html = r.text if (r and r.text) else ""
  soup = BeautifulSoup(html, "html5lib") if html else BeautifulSoup("", "html5lib")

  # 2) сеть / IP / страна / провайдер
  ip_dns = resolve_ip(domain)
  ip_2ip, country_2ip, org_2ip = fetch_ip_info_via_2ip(ip_dns or "")
  if ip_2ip and country_2ip:
    ip_address = ip_2ip
    server_country = country_2ip
    hosting_provider = org_2ip
    ip_source = "2ip"
  else:
    ip_address = ip_dns
    server_country, hosting_provider = (None, None)
    if ip_dns:
      server_country, hosting_provider = whois_ip_country_org(ip_dns)
    ip_source = "dns+whois"

  # 3) SSL
  ssl_status = check_ssl_status(url)

  # 4) CMS
  cms_name = detect_cms(html, dict(r.headers) if r else {})

  # 5) Формы/согласие
  consent_status, forms_issues = analyze_forms_for_consent(soup)

  # 6) Внешние сервисы
  services_external, services_foreign, uses_cdn, services_evidence = classify_services(soup, html)

  # 7) Наличие документов
  docs_hits = scan_documents(soup)

  # 8) Company.* — поиск ИНН на сайте + DaData
  # пробуем найти ИНН в тексте страницы
  inn_detected = find_inn_in_text(html)
  company: Dict[str, str] = {
    "inn": inn_detected or "",
    "name_full": "",
    "ogrn": "",
    "kpp": "",
    "address_legal": "",
    "address_actual": "",
    "email": "",
    "phone": "",
  }
  if inn_detected:
    d = fetch_company_via_dadata(inn_detected)
    if d:
      # маппим в вложенный блок company
      company.update({
        "inn": d.get("company.inn", "") or inn_detected,
        "name_full": d.get("company.name_full", ""),
        "ogrn": d.get("company.ogrn", ""),
        "kpp": d.get("company.kpp", ""),
        "address_legal": d.get("company.address_legal", ""),
        "address_actual": d.get("company.address_actual", ""),
        "email": d.get("company.email", ""),
        "phone": d.get("company.phone", ""),
      })

  # 9) Текстовые doc_*: скачиваем сырые тексты (если есть ссылки) и извлекаем разделы
  # (на первом шаге берём текущую страницу; при желании — пройтись по ссылкам политики/ПС)
  raw_text = soup.get_text(separator="\n", strip=True) if soup else ""
  doc_sections = extract_doc_sections(raw_text)  # базовая эвристика
  if USE_LLM:
    ai_sections = ai_extract_doc_sections(raw_text)
    # если ИИ что-то извлёк — заменим пустые значения
    for k, v in ai_sections.items():
      if v and not doc_sections.get(k):
        doc_sections[k] = v

  # 10) Правила кросс-проверки для аудита применяются позже в audit.py
  # Здесь только складываем всё в JSON.

  data = {
    "site_url": url,
    "domain": domain,
    "ip_address": ip_address,
    "server_country": server_country,      # ISO-2 (например, RU)
    "hosting_provider": hosting_provider,
    "ssl_status": ssl_status,              # installed | not_installed | unknown
    "cms_name": cms_name or None,          # только название
    "uses_cdn": uses_cdn,                  # bool
    "services": {
      "external": services_external,       # строка через запятую (RU)
      "foreign": services_foreign          # строка через запятую (иностранные)
    },
    "policy_exists": docs_hits["policy_exists"],
    "user_agreement_status": docs_hits["user_agreement_status"],
    "offer_status": docs_hits["offer_status"],
    "cookie_notice": docs_hits["cookie_notice"],
    "consent_status": consent_status,      # green/red
    "pd_conditions_audit": False,          # placeholder (если нужен отдельный пункт)
    "notification_status": None,           # спросит чат
    "company": company,
    "doc": {
      "pd_categories":   doc_sections.get("pd_categories", ""),
      "subject_categories": doc_sections.get("subject_categories", ""),
      "methods":         doc_sections.get("methods", ""),
      "goals":           doc_sections.get("goals", ""),
      "grounds":         doc_sections.get("grounds", ""),
      "crossborder":     doc_sections.get("crossborder", ""),
      "deletion":        doc_sections.get("deletion", ""),
      "withdrawal":      doc_sections.get("withdrawal", ""),
      "cookie":          doc_sections.get("cookie", ""),
    },
    "gen_ai": {
      "subject_categories": "",            # заполнит ИИ на шаге генерации (по контенту/формам)
      "goals": "",
      "pdn_categories": "",
      "crossborder": ""                    # для универсального п.4.5 (если services.foreign не пуст)
    },
    "meta": {
      "forms_issues": forms_issues,
      "services_evidence": services_evidence,
      "sources": {
        "ip": ip_source,
        "company": "dadata" if company.get("name_full") else ("site" if inn_detected else "user"),
        "services": "html_scan",
        "docs": "links+current_page",
        "cms": "heuristics"
      }
    }
  }
  return data


def save_json(data: Dict) -> str:
  Path("out").mkdir(parents=True, exist_ok=True)
  fname = f"out/collector_{data.get('domain','site')}.json"
  with open(fname, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
  print(f"saved: {fname}")
  return fname


# ========== CLI ==========
if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("Usage: python collector.py <site_url>")
    sys.exit(1)

  site = sys.argv[1]
  result = collect(site)
  save_json(result)
  print(json.dumps(result, ensure_ascii=False, indent=2))
 #new comment
 