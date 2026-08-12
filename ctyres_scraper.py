#!/usr/bin/env python3
"""
ctyres_scraper.py — Build an offline SQLite copy of the CTyres product catalogue.

WORKFLOW (run in this order):
  python ctyres_scraper.py --stage sizes     # 1. collect all size URLs
  python ctyres_scraper.py --stage inspect   # 2. dump 1 product page so you confirm selectors
  python ctyres_scraper.py --stage products  # 3. full crawl into ctyres.db (resumable)
  python ctyres_scraper.py --stage images    # 4. (optional) download images locally

Selectors below were confirmed against a live page (205-55-16) on 2026-08-10:
  .other_options_box   -> one card per tyre product
  img[src*=brand_logo]  alt=  -> brand name
  h5 span               -> model name
  h6 (direct text)      -> full size label incl. load/speed index, e.g. "205/55/16 91V"
  form h1                -> price, e.g. "£33.69 Each"
  input[name=product_id] -> CTyres internal product code

Only run against a server you're authorised to crawl. Uses a polite delay and is
resumable: re-running --stage products skips sizes already marked scraped.
"""
import argparse, sqlite3, time, pathlib, re, sys
import requests
from bs4 import BeautifulSoup

BASE = "https://www.ctyres.co.uk"
SIZE_INDEX = f"{BASE}/tyre-size"
DB = pathlib.Path("ctyres.db")
IMG_DIR = pathlib.Path("images")
DELAY = 1.5           # seconds between requests — be kind to the client's server
HEADERS = {"User-Agent": "CTyres-offline-backup/1.0 (authorised client work)"}

# ---------- database ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS sizes (
    size_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    slug      TEXT UNIQUE NOT NULL,     -- e.g. "205-55-16"
    label     TEXT,                     -- link text on the size index page
    url       TEXT NOT NULL,
    scraped   INTEGER DEFAULT 0         -- 1 once the products stage has processed it
);
CREATE TABLE IF NOT EXISTS products (
    product_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    size_id     INTEGER REFERENCES sizes(size_id),
    ean         TEXT,                   -- CTyres internal product code
    brand       TEXT,
    model       TEXT,
    tyre_label  TEXT,                   -- full spec e.g. "205/55/16 91V"
    price       REAL,
    image_url   TEXT,
    image_local TEXT,
    source_url  TEXT,                   -- product detail page
    scraped_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(size_id, ean, price)          -- dedupe re-runs
);
"""

def db():
    con = sqlite3.connect(DB, timeout=30)
    con.executescript(SCHEMA)
    return con

def get(url):
    r = requests.get(url, headers=HEADERS, timeout=20)
    r.raise_for_status()
    time.sleep(DELAY)
    return r.text

# ---------- STAGE 1: size index ----------
def stage_sizes():
    con = db(); cur = con.cursor()
    soup = BeautifulSoup(get(SIZE_INDEX), "html.parser")
    n = 0
    for a in soup.select('a[href*="/tyre-search/"]'):
        href = a["href"]
        slug = href.rstrip("/").split("/tyre-search/")[-1]
        if not slug or slug == "size--":       # skip the placeholder row
            continue
        url = href if href.startswith("http") else BASE + href
        cur.execute("INSERT OR IGNORE INTO sizes (slug,label,url) VALUES (?,?,?)",
                    (slug, a.get_text(strip=True), url))
        n += 1
    con.commit()
    print(f"[sizes] stored {cur.execute('SELECT COUNT(*) FROM sizes').fetchone()[0]} sizes "
          f"({n} links seen)")
    con.close()

# ---------- STAGE 2: inspect one product page ----------
def stage_inspect():
    con = db()
    row = con.execute("SELECT url FROM sizes WHERE slug='205-55-16'").fetchone() \
          or con.execute("SELECT url FROM sizes LIMIT 1").fetchone()
    con.close()
    if not row:
        sys.exit("Run --stage sizes first.")
    html = get(row[0])
    pathlib.Path("sample_product_page.html").write_text(html, encoding="utf-8")
    soup = BeautifulSoup(html, "html.parser")
    cards = soup.select(".other_options_box")
    print(f"[inspect] saved sample_product_page.html for {row[0]}")
    print(f"[inspect] found {len(cards)} product cards via .other_options_box")

# ---------- STAGE 3: products ----------
def parse_products(html, size_id, source_url):
    soup = BeautifulSoup(html, "html.parser")
    out = []
    cards = soup.select(".other_options_box")
    for c in cards:
        brand = None
        brand_img = c.select_one("img[src*='brand_logo']")
        if brand_img and brand_img.get("alt"):
            brand = brand_img["alt"].strip()

        model_el = c.select_one("h5 span")
        model = model_el.get_text(strip=True) if model_el else None

        tyre_label = None
        h6 = c.select_one("h6")
        if h6:
            txt = h6.find(string=True, recursive=False)
            if txt:
                tyre_label = txt.strip()

        price = None
        h1 = c.select_one("form h1")
        if h1:
            m = re.search(r"£\s*([\d,]+\.\d{2})", h1.get_text())
            if m:
                price = float(m.group(1).replace(",", ""))

        pid_input = c.select_one("input[name='product_id']")
        ean = pid_input["value"] if pid_input and pid_input.get("value") else None

        img = c.select_one("img.th")
        img_url = None
        if img and img.get("src"):
            src = img["src"]
            img_url = src if src.startswith("http") else BASE + src

        link = c.select_one("a[href*='/shop/']")
        product_url = link["href"] if link and link.get("href") else source_url

        if model or price:
            out.append((size_id, ean, brand, model, tyre_label, price, img_url, product_url))
    return out

def stage_products():
    con = db(); cur = con.cursor()
    sizes = cur.execute("SELECT size_id,url FROM sizes WHERE scraped=0").fetchall()
    total_sizes = cur.execute("SELECT COUNT(*) FROM sizes").fetchone()[0]
    done_already = total_sizes - len(sizes)
    total = cur.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    print(f"[products] resuming: {done_already}/{total_sizes} sizes already scraped, "
          f"{len(sizes)} remaining, {total} product rows so far")
    for i, (size_id, url) in enumerate(sizes, 1):
        try:
            rows = parse_products(get(url), size_id, url)
            cur.executemany("""INSERT OR IGNORE INTO products
                 (size_id,ean,brand,model,tyre_label,price,image_url,source_url)
                 VALUES (?,?,?,?,?,?,?,?)""", rows)
            cur.execute("UPDATE sizes SET scraped=1 WHERE size_id=?", (size_id,))
            con.commit()
            total += len(rows)
            print(f"[{done_already+i}/{total_sizes}] {url} -> {len(rows)} products (total {total})", flush=True)
        except Exception as e:
            print(f"[{done_already+i}/{total_sizes}] FAILED {url}: {e}", flush=True)
    print(f"[products] done. {total} product rows.")
    con.close()

# ---------- STAGE 4: images ----------
def stage_images():
    IMG_DIR.mkdir(exist_ok=True)
    con = db(); cur = con.cursor()
    rows = cur.execute("SELECT product_id,image_url FROM products "
                       "WHERE image_url IS NOT NULL AND image_local IS NULL").fetchall()
    for pid, url in rows:
        try:
            ext = url.split(".")[-1].split("?")[0][:4]
            path = IMG_DIR / f"{pid}.{ext}"
            path.write_bytes(requests.get(url, headers=HEADERS, timeout=20).content)
            cur.execute("UPDATE products SET image_local=? WHERE product_id=?", (str(path), pid))
            con.commit(); time.sleep(DELAY)
            print(f"saved {path}")
        except Exception as e:
            print(f"img fail {pid}: {e}")
    con.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True,
                    choices=["sizes","inspect","products","images"])
    a = ap.parse_args()
    {"sizes":stage_sizes,"inspect":stage_inspect,
     "products":stage_products,"images":stage_images}[a.stage]()
