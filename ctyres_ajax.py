#!/usr/bin/env python3
"""
Stage 2 crawler: pulls each size's listing from CTyres' own AJAX endpoint
(index_ajax.php), which returns the product grid that is NOT always present
in the server-rendered page. This recovers sizes the plain page-crawl missed.
Resumable: re-run until 'remaining' is 0.
"""
import sqlite3, re, sys, time, requests, concurrent.futures as cf
from bs4 import BeautifulSoup

DB = '/tmp/ctyres_work/ctyres_catalogue.db'
AJAX = 'https://www.ctyres.co.uk/index_ajax.php'
H = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
     'X-Requested-With':'XMLHttpRequest','Referer':'https://www.ctyres.co.uk/'}
WORKERS = 5

def setup():
    con = sqlite3.connect(DB, timeout=60)
    cols = {r[1] for r in con.execute('PRAGMA table_info(sizes)')}
    if 'ajax_done' not in cols:
        con.execute('ALTER TABLE sizes ADD COLUMN ajax_done INTEGER DEFAULT 0')
    con.commit(); return con

def parse(html, size_id):
    soup = BeautifulSoup(html, 'html.parser'); out=[]
    for c in soup.select('.other_options_box'):
        bi = c.select_one("img[src*='brand_logo']")
        brand = bi['alt'].strip() if bi and bi.get('alt') else None
        me = c.select_one('h5 span'); model = me.get_text(strip=True) if me else None
        label=None; h6=c.select_one('h6')
        if h6:
            t=h6.find(string=True, recursive=False)
            if t: label=t.strip()
        price=None; h1=c.select_one('form h1')
        if h1:
            m=re.search(r'£\s*([\d,]+\.\d{2})', h1.get_text())
            if m: price=float(m.group(1).replace(',',''))
        pi=c.select_one("input[name='product_id']")
        ean=pi['value'] if pi and pi.get('value') else None
        im=c.select_one('img.th'); img=None
        if im and im.get('src'):
            s=im['src']; img = s if s.startswith('http') else 'https://www.ctyres.co.uk'+s
        a=c.select_one("a[href*='/shop/']"); url=a['href'] if a and a.get('href') else None
        if not brand and url:
            m=re.search(r'/shop/([^/]+)/', url)
            if m: brand=m.group(1).replace('-',' ').strip()
        if model or price:
            out.append((size_id, ean, brand, model, label, price, img, url))
    return out

def fetch(job):
    size_id, slug = job
    m = re.fullmatch(r'(\d+)-(\d+)-(\d+)([A-Z]*)', slug)
    if not m: return size_id, [], 'unparsable'
    w,h,r = m.group(1), m.group(2), m.group(3)
    rows, err = [], None
    for act in ('fitted','delivery'):
        try:
            resp = requests.get(AJAX, params={'action':'fitted_filter_ajx','fitted_action':act,
                    'width':w,'height':h,'rim':r,'sort_by':'price_asc'}, headers=H, timeout=30)
            if resp.status_code==200:
                got = parse(resp.text, size_id)
                if got: rows = got; break
            else: err=f'HTTP {resp.status_code}'
        except Exception as e:
            err=str(e)[:60]
        time.sleep(0.4)
    return size_id, rows, err

def main(budget=150):
    con = setup(); cur = con.cursor()
    jobs = cur.execute('SELECT size_id, slug FROM sizes WHERE ajax_done=0').fetchall()
    total = cur.execute('SELECT COUNT(*) FROM sizes').fetchone()[0]
    print(f'remaining {len(jobs)} of {total}', flush=True)
    jobs = jobs[:budget]
    added=0; start=time.time()
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for size_id, rows, err in ex.map(fetch, jobs):
            if rows:
                before = cur.execute('SELECT COUNT(*) FROM products').fetchone()[0]
                cur.executemany("""INSERT OR IGNORE INTO products
                    (size_id,ean,brand,model,tyre_label,price,image_url,source_url)
                    VALUES (?,?,?,?,?,?,?,?)""", rows)
                added += cur.execute('SELECT COUNT(*) FROM products').fetchone()[0]-before
            cur.execute('UPDATE sizes SET ajax_done=1 WHERE size_id=?', (size_id,))
            con.commit()
    left = cur.execute('SELECT COUNT(*) FROM sizes WHERE ajax_done=0').fetchone()[0]
    withstock = cur.execute('SELECT COUNT(DISTINCT size_id) FROM products').fetchone()[0]
    print(f'+{added} new rows in {time.time()-start:.0f}s | products={cur.execute("SELECT COUNT(*) FROM products").fetchone()[0]}'
          f' | sizes with stock={withstock} | remaining={left}', flush=True)
    con.close()

if __name__=='__main__':
    main(int(sys.argv[1]) if len(sys.argv)>1 else 150)
