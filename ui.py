"""VARE UI kit - threat-ops console theme and reusable components for Streamlit.

All dynamic text is HTML-escaped: scan evidence comes from remote targets and must never be trusted.
"""
import html
import math

import streamlit as st

SEV_TONE = {"Critical": "crit", "High": "danger", "Medium": "warn", "Low": "low", "Info": "info"}

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

:root{
  --bg:#070B10; --panel:#0C131B; --panel2:#111B26; --line:#1A2836; --line2:#26394C;
  --text:#D6E2EE; --mute:#7F93A8; --dim:#4E6176;
  --cyan:#39D0F0; --green:#2EE6A6; --red:#FF4D6D; --amber:#FFB020; --violet:#C084FC; --yellow:#E8D44D;
  --display:'Chakra Petch','IBM Plex Sans',sans-serif;
  --body:'IBM Plex Sans',system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,Consolas,monospace;
}
.t-ok{--tc:var(--green)} .t-info{--tc:var(--cyan)} .t-warn{--tc:var(--amber)} .t-danger{--tc:var(--red)}
.t-crit{--tc:var(--violet)} .t-low{--tc:var(--yellow)} .t-mute{--tc:var(--mute)}

/* ---------- base ---------- */
.stApp{
  background:
    radial-gradient(900px 500px at 92% -8%, rgba(57,208,240,.09), transparent 60%),
    linear-gradient(rgba(57,208,240,.035) 1px, transparent 1px) 0 0/44px 44px,
    linear-gradient(90deg, rgba(57,208,240,.035) 1px, transparent 1px) 0 0/44px 44px,
    var(--bg);
  font-family:var(--body);
}
html,body,[class*="css"]{font-family:var(--body)}
#MainMenu, footer, [data-testid="stDecoration"]{visibility:hidden}
header[data-testid="stHeader"]{background:transparent}
.block-container{padding-top:2rem;padding-bottom:4rem;max-width:1240px}
h1,h2,h3,h4{font-family:var(--display)!important;letter-spacing:.005em;color:#EAF3FB}
h4{font-size:1.02rem!important}
p,li,label{color:var(--text)}
[data-testid="stCaptionContainer"]{color:var(--mute)}
code,pre,kbd{font-family:var(--mono)!important}
::-webkit-scrollbar{width:9px;height:9px} ::-webkit-scrollbar-thumb{background:var(--line2);border-radius:9px}
::-webkit-scrollbar-track{background:transparent}
hr{border-color:var(--line)!important}

/* ---------- sidebar ---------- */
section[data-testid="stSidebar"]{background:#080D13;border-right:1px solid var(--line)}
section[data-testid="stSidebar"] .block-container,section[data-testid="stSidebar"] > div{padding-top:1.2rem}
.brand{display:flex;gap:.75rem;align-items:center;padding:.2rem .4rem 1rem}
.brand svg{width:38px;height:38px;flex:none;filter:drop-shadow(0 0 8px rgba(57,208,240,.5))}
.brand b{display:block;font:700 1.35rem/1 var(--display);letter-spacing:.14em;color:#fff}
.brand span{display:block;font:400 .72rem/1.3 var(--body);color:var(--mute);margin-top:.25rem}
.sidestat{margin:.4rem .2rem 1rem;padding:.7rem .8rem;border:1px solid var(--line);border-radius:8px;background:var(--panel);
  font:400 .76rem/1.7 var(--mono);color:var(--mute)}
.sidestat b{color:var(--text);font-weight:500}
.sidestat .on{color:var(--green)}
.notice{margin:.4rem .2rem;padding:.75rem .85rem;border:1px solid rgba(255,176,32,.35);border-left:3px solid var(--amber);
  border-radius:6px;background:rgba(255,176,32,.06);font-size:.8rem;line-height:1.5;color:#E9D6AE}
section[data-testid="stSidebar"] .stButton>button{
  width:100%;justify-content:flex-start;background:transparent;border:1px solid transparent;border-radius:6px;
  color:var(--mute);font:500 .92rem var(--display);padding:.55rem .8rem;transition:background .15s,color .15s}
section[data-testid="stSidebar"] .stButton>button:hover{background:var(--panel2);color:var(--text);border-color:transparent}
section[data-testid="stSidebar"] .stButton>button[kind="primary"],
section[data-testid="stSidebar"] .stButton>button[data-testid="stBaseButton-primary"]{
  background:linear-gradient(90deg,rgba(57,208,240,.16),rgba(57,208,240,0));color:#fff;
  box-shadow:inset 2px 0 0 var(--cyan);border-color:transparent}
section[data-testid="stSidebar"] .stButton>button p{font-family:var(--display)}

/* ---------- buttons ---------- */
.stButton>button,.stDownloadButton>button{
  font:500 .9rem var(--display);letter-spacing:.02em;border-radius:6px;border:1px solid var(--line2);
  background:var(--panel2);color:var(--text);padding:.5rem 1.1rem;transition:all .15s}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:var(--cyan);color:var(--cyan);background:rgba(57,208,240,.06)}
.stButton>button[kind="primary"],.stButton>button[data-testid="stBaseButton-primary"]{
  background:var(--cyan);color:#03222B;border-color:var(--cyan);font-weight:700}
.stButton>button[kind="primary"]:hover,.stButton>button[data-testid="stBaseButton-primary"]:hover{
  background:#6FE0F7;color:#03222B;box-shadow:0 0 18px rgba(57,208,240,.45)}
.stButton>button:disabled{background:var(--panel)!important;color:var(--dim)!important;border-color:var(--line)!important;box-shadow:none!important}
.stButton>button:focus-visible,.stDownloadButton>button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}

/* ---------- inputs ---------- */
.stTextInput input,.stTextArea textarea{
  background:#0A1118!important;border:1px solid var(--line2)!important;border-radius:6px!important;
  color:var(--text)!important;font-family:var(--mono)!important;font-size:.88rem!important}
.stTextInput input:focus,.stTextArea textarea:focus{border-color:var(--cyan)!important;box-shadow:0 0 0 1px var(--cyan)!important}
[data-baseweb="select"]>div{background:#0A1118!important;border-color:var(--line2)!important;border-radius:6px!important}
[data-testid="stWidgetLabel"] p{color:var(--mute);font-size:.84rem}
[data-testid="stFileUploaderDropzone"]{background:var(--panel);border:1px dashed var(--line2);border-radius:8px;transition:border-color .15s}
[data-testid="stFileUploaderDropzone"]:hover{border-color:var(--cyan)}

/* ---------- metrics, tabs, expanders, alerts ---------- */
[data-testid="stMetric"]{background:var(--panel);border:1px solid var(--line);border-left:2px solid var(--cyan);
  border-radius:6px;padding:.85rem 1rem}
[data-testid="stMetricLabel"] p{color:var(--mute)!important;font:400 .76rem var(--mono)!important}
[data-testid="stMetricValue"]{font-family:var(--display)!important;font-weight:600!important;color:#fff}
.stTabs [data-baseweb="tab-list"]{gap:.2rem;border-bottom:1px solid var(--line)}
.stTabs [data-baseweb="tab"]{font:500 .9rem var(--display);color:var(--mute);padding:.6rem 1rem;background:transparent}
.stTabs [aria-selected="true"]{color:var(--cyan)!important}
.stTabs [data-baseweb="tab-highlight"]{background:var(--cyan)!important;height:2px}
.stTabs [data-baseweb="tab-border"]{background:transparent!important}
[data-testid="stExpander"]{border:1px solid var(--line)!important;border-radius:8px!important;background:var(--panel);overflow:hidden}
[data-testid="stExpander"] summary:hover{background:rgba(57,208,240,.04)}
[data-testid="stAlert"]{border-radius:6px;border:1px solid var(--line2);background:var(--panel)}
[data-testid="stProgress"] div[role="progressbar"]>div,[data-testid="stProgress"] [data-baseweb="progress-bar"] div>div{
  background:linear-gradient(90deg,var(--cyan),var(--green))!important}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:8px;overflow:hidden}

/* ---------- hero + radar (the one big moment) ---------- */
.hero{position:relative;display:grid;grid-template-columns:1fr auto;gap:2rem;align-items:center;overflow:hidden;
  padding:2rem 2.2rem;border:1px solid var(--line2);border-radius:12px;margin-bottom:1.4rem;
  background:radial-gradient(600px 260px at 85% 50%,rgba(57,208,240,.10),transparent 70%),var(--panel)}
.hero:before,.hero:after{content:"";position:absolute;width:16px;height:16px;border:2px solid var(--cyan);opacity:.8}
.hero:before{top:10px;left:10px;border-right:0;border-bottom:0}
.hero:after{bottom:10px;right:10px;border-left:0;border-top:0}
.hero h1{margin:0 0 .6rem;font-size:2.35rem!important;line-height:1.1;font-weight:700}
.hero p{margin:0 0 1rem;max-width:52ch;color:var(--mute);font-size:1rem;line-height:1.6}
.radar{width:210px;height:210px;flex:none}
.radar svg{width:100%;height:100%;overflow:visible}
.radar .ring{fill:none;stroke:rgba(57,208,240,.28);stroke-width:.7}
.radar .cross{stroke:rgba(57,208,240,.18);stroke-width:.6}
.radar .sweep{transform-origin:100px 100px;animation:spin 5s linear infinite}
.radar .blip{fill:var(--red);animation:blip 5s ease-out infinite}
.radar .blip.b2{animation-delay:1.6s;fill:var(--amber)} .radar .blip.b3{animation-delay:3.2s;fill:var(--green)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes blip{0%,8%{opacity:1;r:3.4}45%,100%{opacity:.08;r:2}}

/* ---------- page header, sections ---------- */
.pagehead{margin:0 0 1.5rem;padding-bottom:1.1rem;border-bottom:1px solid var(--line)}
.crumb{font:400 .78rem var(--mono);color:var(--dim);margin-bottom:.5rem}
.crumb i{color:var(--cyan);font-style:normal}
.pagehead h1{margin:0 0 .4rem;font-size:1.9rem!important;font-weight:700}
.pagehead p{margin:0 0 .8rem;color:var(--mute);max-width:78ch;line-height:1.55}
.section{display:flex;align-items:center;gap:.9rem;margin:1.8rem 0 .9rem}
.section h3{margin:0;font-size:1.05rem!important;font-weight:600;white-space:nowrap}
.section:after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
.section small{color:var(--mute);font-size:.8rem;order:3}

/* ---------- chips, banners, cards ---------- */
.chips{display:flex;flex-wrap:wrap;gap:.4rem}
.chip{display:inline-flex;align-items:center;gap:.35rem;font:400 .74rem var(--mono);padding:.18rem .6rem;border-radius:999px;
  color:var(--tc,var(--mute));border:1px solid color-mix(in srgb,var(--tc,var(--mute)) 45%,transparent);
  background:color-mix(in srgb,var(--tc,var(--mute)) 10%,transparent)}
.chip.dot:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--tc);box-shadow:0 0 8px var(--tc);animation:pulse 2s infinite}
@keyframes pulse{50%{opacity:.35}}
.banner{display:flex;gap:1rem;align-items:center;padding:1rem 1.2rem;border-radius:8px;margin:.3rem 0 1.2rem;
  border:1px solid color-mix(in srgb,var(--tc) 50%,transparent);border-left:4px solid var(--tc);
  background:linear-gradient(90deg,color-mix(in srgb,var(--tc) 14%,transparent),var(--panel) 70%)}
.banner .bg{flex:none;width:34px;height:34px;border-radius:50%;display:grid;place-items:center;
  font:700 1rem var(--display);color:#04121A;background:var(--tc);box-shadow:0 0 16px color-mix(in srgb,var(--tc) 60%,transparent)}
.banner .bt{font:600 1.15rem var(--display);color:#fff}
.banner .bd{font-size:.88rem;color:var(--mute);margin-top:.15rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1.2rem 1.25rem 1.1rem;margin-bottom:.6rem;
  transition:border-color .15s}
.card:hover{border-color:var(--line2)}
.card .ic{width:38px;height:38px;border-radius:8px;display:grid;place-items:center;margin-bottom:.8rem;
  color:var(--tc);background:color-mix(in srgb,var(--tc) 12%,transparent);border:1px solid color-mix(in srgb,var(--tc) 35%,transparent)}
.card .ic svg{width:20px;height:20px}
.card h4{margin:0 0 .4rem}
.card p{margin:0 0 .9rem;color:var(--mute);font-size:.88rem;line-height:1.55;min-height:4.3em}
.empty{border:1px dashed var(--line2);border-radius:10px;padding:2rem;text-align:center;background:var(--panel)}
.empty b{display:block;font:600 1rem var(--display);color:#fff;margin-bottom:.3rem}
.empty span{color:var(--mute);font-size:.9rem}

/* ---------- gauge ---------- */
.gauge{position:relative;width:180px;margin:.2rem auto}
.gauge svg{width:180px;height:180px;transform:rotate(-90deg)}
.gauge circle{fill:none}
.gauge .ticks{stroke:var(--line2);stroke-width:4;stroke-dasharray:1.5 4.5}
.gauge .track{stroke:var(--line);stroke-width:9}
.gauge .arc{stroke:var(--tc);stroke-width:9;stroke-linecap:round;filter:drop-shadow(0 0 6px color-mix(in srgb,var(--tc) 65%,transparent));
  animation:fill 1.2s cubic-bezier(.2,.7,.2,1)}
@keyframes fill{from{stroke-dashoffset:var(--c)}}
.gauge .gv{position:absolute;top:0;left:0;width:180px;height:180px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .gv b{font:700 2.6rem/1 var(--display);color:#fff}
.gauge .gv span{font:400 .74rem var(--mono);color:var(--mute);margin-top:.2rem}
.gauge .gl{text-align:center;margin-top:.5rem;font:500 .88rem var(--display);color:var(--tc)}

/* ---------- severity bar, findings, plan ---------- */
.sevbar{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--line);gap:2px;margin:.3rem 0 .7rem}
.sevbar i{background:var(--tc);display:block}
.sevlegend{display:flex;flex-wrap:wrap;gap:1.1rem;font:400 .8rem var(--mono);color:var(--mute);margin-bottom:.5rem}
.sevlegend span:before{content:"";display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--tc);margin-right:.4rem}
.sevlegend b{color:#fff;font-weight:500}
.fbody{padding:.2rem .1rem .3rem}
.fbody .lbl{font:500 .78rem var(--mono);color:var(--mute);margin:1rem 0 .4rem}
.evidence{font:400 .82rem/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;background:#080D13;
  border:1px solid var(--line);border-left:2px solid var(--tc);border-radius:6px;padding:.7rem .9rem;color:#B9CCDD}
.fbody ol,.plan ol{margin:.2rem 0 0;padding-left:1.2rem;color:var(--text);font-size:.9rem;line-height:1.65}
.phase{margin:1.4rem 0 .6rem;font:600 1.02rem var(--display);color:#fff}
.plan{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--tc);border-radius:8px;padding:.85rem 1.1rem;margin-bottom:.6rem}
.plan .pt{font:600 .95rem var(--display);color:#fff;margin-bottom:.4rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}

/* ---------- pipeline + terminal ---------- */
.pipe{display:flex;align-items:stretch;gap:0;margin:.4rem 0 1.2rem;flex-wrap:wrap}
.node{flex:1;min-width:150px;padding:.9rem 1rem;border-radius:8px;background:var(--panel);
  border:1px solid color-mix(in srgb,var(--tc) 55%,transparent);box-shadow:inset 0 0 24px color-mix(in srgb,var(--tc) 8%,transparent)}
.node b{display:block;font:600 1rem var(--display);color:#fff}
.node span{display:block;font:400 .78rem var(--mono);color:var(--tc);margin-top:.25rem}
.link{flex:0 0 42px;align-self:center;height:2px;background:repeating-linear-gradient(90deg,var(--tc) 0 6px,transparent 6px 10px);position:relative}
.link:after{content:"";position:absolute;right:-1px;top:-4px;border:5px solid transparent;border-left:8px solid var(--tc);border-right:0}
.term{font:400 .84rem var(--mono);color:var(--green);background:#060A0E;border:1px solid var(--line);border-radius:6px;padding:.55rem .8rem}
.term .p{color:var(--cyan);margin-right:.5rem}
.term .cur{display:inline-block;width:8px;height:1em;background:var(--green);vertical-align:text-bottom;margin-left:3px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}

@media (max-width:820px){.hero{grid-template-columns:1fr;padding:1.4rem}.radar{display:none}.hero h1{font-size:1.8rem!important}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

_ICONS = {
    "video": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="13" height="14" rx="2"/><path d="m16 10 5-3v10l-5-3"/><circle cx="9.5" cy="12" r="2.2"/></svg>',
    "prompt": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4 6v6c0 4.5 3.2 7.8 8 9 4.8-1.2 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/></svg>',
    "web": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
}

LOGO = ('<svg viewBox="0 0 40 40" fill="none" stroke="#39D0F0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M20 3 6 9v11c0 8.5 6 14.5 14 17 8-2.5 14-8.5 14-17V9z"/>'
        '<circle cx="20" cy="19" r="4"/><path d="M20 15v-4M20 23v4M16 19h-4M24 19h4" stroke-width="1.6"/></svg>')


def esc(x):
    """Escape for HTML and neutralise '$' so Streamlit doesn't treat it as LaTeX."""
    return html.escape(str(x)).replace("$", "&#36;")


def render(markup, target=None):
    flat = "".join(line.strip() for line in markup.splitlines())
    (target or st).markdown(flat, unsafe_allow_html=True)


def inject_css():
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def show_df(df, **kw):
    """Full-width, index-less dataframe that works across Streamlit versions."""
    try:
        st.dataframe(df, width="stretch", hide_index=True, **kw)
    except Exception:
        st.dataframe(df, use_container_width=True, hide_index=True, **kw)


# ------------------------------------------------------------------ tones
def tone_risk(v):
    return "ok" if v < 35 else "warn" if v < 60 else "danger"


def tone_score(v):
    return "ok" if v >= 80 else "warn" if v >= 60 else "danger"


# ------------------------------------------------------------------ components
def chip(text, tone="mute", dot=False):
    return f'<span class="chip t-{tone}{" dot" if dot else ""}">{esc(text)}</span>'


def chips(items, target=None):
    render('<div class="chips">' + "".join(chip(*i) if isinstance(i, tuple) else chip(i) for i in items) + "</div>", target)


def brand(scan_count, last):
    render(f'<div class="brand">{LOGO}<div><b>VARE</b><span>Vulnerability assessment<br>&amp; reverse engineering</span></div></div>', st.sidebar)
    render(f'<div class="sidestat"><span class="on">&#9679;</span> engine <b>online</b><br>'
           f'scans this session <b>{scan_count}</b><br>last run <b>{esc(last)}</b></div>', st.sidebar)


def notice(text, target=None):
    render(f'<div class="notice">{esc(text)}</div>', target)


def page_header(path, title, desc, tags=()):
    render(f'<div class="pagehead"><div class="crumb">vare / <i>{esc(path)}</i></div><h1>{esc(title)}</h1><p>{esc(desc)}</p>'
           + ('<div class="chips">' + "".join(chip(*t) for t in tags) + "</div>" if tags else "") + "</div>")


def section(title, note=""):
    render(f'<div class="section"><h3>{esc(title)}</h3>{f"<small>{esc(note)}</small>" if note else ""}</div>')


def radar():
    rings = "".join(f'<circle class="ring" cx="100" cy="100" r="{r}"/>' for r in (24, 48, 72, 96))
    return ('<div class="radar" aria-hidden="true"><svg viewBox="0 0 200 200"><defs>'
            '<linearGradient id="sw" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#39D0F0" stop-opacity="0"/>'
            '<stop offset="1" stop-color="#39D0F0" stop-opacity=".55"/></linearGradient></defs>'
            f'{rings}<line class="cross" x1="4" y1="100" x2="196" y2="100"/><line class="cross" x1="100" y1="4" x2="100" y2="196"/>'
            '<g class="sweep"><path d="M100 100 L100 4 A96 96 0 0 1 168 32 Z" fill="url(#sw)" transform="rotate(-38 100 100)"/></g>'
            '<circle class="blip" cx="140" cy="62" r="3"/><circle class="blip b2" cx="62" cy="128" r="3"/>'
            '<circle class="blip b3" cx="126" cy="146" r="3"/><circle cx="100" cy="100" r="3" fill="#39D0F0"/></svg></div>')


def hero(title, text, tags=()):
    tag_html = '<div class="chips">' + "".join(chip(*t) for t in tags) + "</div>" if tags else ""
    render(f'<div class="hero"><div><h1>{esc(title)}</h1><p>{esc(text)}</p>{tag_html}</div>{radar()}</div>')


def module_card(kind, tone, title, text, tags):
    render(f'<div class="card t-{tone}"><div class="ic">{_ICONS[kind]}</div><h4>{esc(title)}</h4><p>{esc(text)}</p>'
           + '<div class="chips">' + "".join(chip(t) for t in tags) + "</div></div>")


def empty(title, hint):
    render(f'<div class="empty"><b>{esc(title)}</b><span>{esc(hint)}</span></div>')


def banner(tone, title, detail=""):
    glyph = {"danger": "&#10005;", "warn": "!", "ok": "&#10003;", "info": "i", "crit": "!"}.get(tone, "i")
    render(f'<div class="banner t-{tone}"><div class="bg">{glyph}</div><div><div class="bt">{esc(title)}</div>'
           f'<div class="bd">{esc(detail)}</div></div></div>')


def gauge(value, label, tone, sub="/ 100", display=None):
    v = max(0.0, min(100.0, float(value or 0)))
    c = 2 * math.pi * 52
    off = c * (1 - v / 100)
    shown = display if display is not None else f"{v:.0f}"
    render(f'<div class="gauge t-{tone}"><svg viewBox="0 0 140 140" role="img" aria-label="{esc(label)}: {esc(shown)}">'
           f'<circle class="ticks" cx="70" cy="70" r="64"/><circle class="track" cx="70" cy="70" r="52"/>'
           f'<circle class="arc" cx="70" cy="70" r="52" stroke-dasharray="{c:.1f}" stroke-dashoffset="{off:.1f}" style="--c:{c:.1f}"/></svg>'
           f'<div class="gv"><b>{esc(shown)}</b><span>{esc(sub)}</span></div><div class="gl">{esc(label)}</div></div>')


def sev_bar(counts, order):
    total = sum(counts.get(k, 0) for k in order)
    segs = "".join(f'<i class="t-{SEV_TONE[k]}" style="flex:{counts[k]}"></i>' for k in order if counts.get(k))
    legend = "".join(f'<span class="t-{SEV_TONE[k]}"><b>{counts.get(k, 0)}</b> {k.lower()}</span>' for k in order)
    render(f'<div class="sevbar">{segs if total else ""}</div><div class="sevlegend">{legend}</div>')


def finding_body(f, owasp_name):
    tone = SEV_TONE.get(f["severity"], "info")
    meta = "".join([chip(f["severity"], tone, dot=True), chip(f'ID {f["fid"]}'), chip(f'CVSS {f["cvss"]}'),
                    chip(f'exploitability {f["exploitability"]}'), chip(f'{f["owasp"]} {owasp_name}', "info")])
    steps = "".join(f"<li>{esc(s)}</li>" for s in f["remediation"])
    render(f'<div class="fbody t-{tone}"><div class="chips">{meta}</div><div class="lbl">evidence</div>'
           f'<div class="evidence">{esc(f["evidence"] or "none captured")}</div><div class="lbl">how to fix</div><ol>{steps}</ol></div>')


def plan_phase(ph):
    render(f'<div class="phase">{esc(ph["phase"])}</div>')
    if not ph["items"]:
        render('<div class="empty"><span>Nothing to do in this phase.</span></div>')
    for it in ph["items"]:
        tone = SEV_TONE.get(it["severity"], "info")
        steps = "".join(f"<li>{esc(s)}</li>" for s in it["steps"])
        render(f'<div class="plan t-{tone}"><div class="pt">{esc(it["title"])}{chip(it["severity"], tone)}'
               f'{chip("risk " + str(it["risk"]))}{chip(it["finding"])}</div><ol>{steps}</ol></div>')


def pipeline(nodes):
    """nodes: list of (title, subtitle, tone)."""
    parts = []
    for i, (t, s, tone) in enumerate(nodes):
        if i:
            parts.append(f'<div class="link t-{nodes[i - 1][2]}"></div>')
        parts.append(f'<div class="node t-{tone}"><b>{esc(t)}</b><span>{esc(s)}</span></div>')
    render('<div class="pipe">' + "".join(parts) + "</div>")


def term(text, target=None):
    render(f'<div class="term"><span class="p">$</span>{esc(text)}<span class="cur"></span></div>', target)
