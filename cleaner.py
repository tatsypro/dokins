# File: cleaner.py — очистка HTML страниц документов (Политика/Куки/ПС/Оферта) для ИИ-экстракции
# Назначение: превращает сырой HTML в компактный «юридический» текст без скриптов/меню/баннеров и прочего шума.
#
# CLI:
#   python cleaner.py --kind policy --in file.html
#   python cleaner.py --kind cookie --in file.html > cleaned.txt
#
# API:
#   from cleaner import clean_html_to_text
#   text = clean_html_to_text(html, kind="policy")

import re
import sys
import argparse
from typing import Literal

from bs4 import BeautifulSoup, Comment

Kind = Literal["policy", "cookie", "agreement", "offer"]

# Классы/идентификаторы, которые считаем «шумом»
NOISE_CLASSES = re.compile(
    r"(menu|navbar|nav|breadcrumb|breadcrumbs|sidebar|aside|popup|modal|"
    r"subscribe|subscription|banner|cookie|footer|header|promo|share|social|"
    r"search|form|contact|callback|widget|captcha|comments?)",
    re.I,
)

# Теги, которые вырезаем целиком
DROP_TAGS = set(["script", "style", "noscript", "svg"])

# Роли/атрибуты, по которым считаем узел неинформативным
def is_noise_node(tag) -> bool:
    if not getattr(tag, "attrs", None):
        return False
    # скрытые/презентационные
    if tag.get("hidden") is not None:
        return True
    if tag.get("aria-hidden") in ("true", True):
        return True
    role = (tag.get("role") or "").lower()
    if role in ("navigation", "banner", "complementary", "search", "presentation"):
        return True
    # классы/ид
    classes = " ".join(tag.get("class") or [])
    if NOISE_CLASSES.search(classes):
        return True
    if NOISE_CLASSES.search(tag.get("id") or ""):
        return True
    return False

# Ищем «основной» контейнер документа
MAIN_CANDIDATES = [
    "main", "article", "[role='main']",
    ".content", ".container", ".layout__content", ".policy", ".privacy", ".offer", ".terms",
]

def pick_main_container(soup: BeautifulSoup):
    # 1) Явные кандидаты
    for sel in MAIN_CANDIDATES:
        node = soup.select_one(sel)
        if node:
            return node
    # 2) Фолбэк — body
    return soup.body or soup

# Нормализация текста: схлопывание пробелов/переводов строк
def normalize_text(s: str) -> str:
    s = re.sub(r"\r", "", s)
    s = re.sub(r"[ \t]+", " ", s)
    # сохраняем пустые строки между абзацами/заголовками
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = s.strip()
    return s

def clean_html_to_text(html: str, kind: Kind = "policy") -> str:
    if not html:
        return ""

    soup = BeautifulSoup(html, "html5lib")

    # Удаляем комментарии и мусорные теги
    for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
        c.extract()
    for t in soup.find_all(DROP_TAGS):
        t.decompose()

    root = pick_main_container(soup)

    # Удаляем шумовые блоки сверху вниз
    for tag in list(root.find_all(True)):
        if is_noise_node(tag):
            tag.decompose()

    # Собираем «юридический» текст из важной структуры
    parts = []
    # Сначала заголовки — помогают модели видеть структуру
    for h in root.find_all(re.compile(r"^h[1-6]$", re.I)):
        txt = h.get_text(" ", strip=True)
        if txt:
            parts.append(txt)

    # Абзацы, списки, таблицы
    for el in root.find_all(["p", "li", "td", "th"]):
        txt = el.get_text(" ", strip=True)
        if txt:
            parts.append(txt)

    text = "\n".join(parts)

    # Убираем артефакты типа «onclick=», «var x=», «function() {» если просочилось
    # (не агрессивно, чтобы не вырезать юридический текст)
    lines = []
    for line in text.splitlines():
        l = line.strip()
        if not l:
            lines.append("")
            continue
        # если слишком много небуквенных — вероятно, это кусок кода
        non_alpha_ratio = sum(ch for ch in [1 for ch in l if not ch.isalnum() and not ch.isspace()]) / max(len(l), 1)
        if non_alpha_ratio > 0.6 and len(l) > 40:
            continue
        # явные JS-паттерны
        if re.search(r"\b(function|var|let|const|=>|\(\)\s*=>|\{|\};)\b", l) and len(l) > 40:
            continue
        lines.append(l)
    text = "\n".join(lines)

    # Для некоторых видов документов можно мягко отфильтровать нерелевантные строки
    if kind == "cookie":
        # чаще всего короткие уведомления, убираем маркетинговые хвосты
        pass
    elif kind in ("agreement", "offer"):
        # обычно много пунктов/нумерации — сохраняем по максимуму
        pass

    return normalize_text(text)

# --- CLI ---
def _main():
    ap = argparse.ArgumentParser(description="Докинс: очистка HTML → юридический текст")
    ap.add_argument("--kind", choices=["policy", "cookie", "agreement", "offer"], default="policy")
    ap.add_argument("--in", dest="infile", required=True, help="Путь к HTML-файлу")
    args = ap.parse_args()

    with open(args.infile, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    cleaned = clean_html_to_text(html, kind=args.kind)  # type: ignore
    sys.stdout.write(cleaned)

if __name__ == "__main__":
    _main()