# VARE - Vulnerability Assessment System (Streamlit)

## Run
    pip install -r requirements.txt
    streamlit run app.py
(Optional: `ffmpeg`/`ffprobe` install ho to video metadata check bhi chalta hai.)

## Modules
- modules/video_detector.py   - original vs fake video (heuristic forensic indicators)
- modules/prompt_injection.py - injection detector + client<->server gateway
- modules/web_scanner.py      - non-intrusive web vulnerability scanner (OWASP Top 10, risk score, remediation)

Sirf authorised targets scan karein. Video detector probability deta hai, proof nahi.

## UI
- `ui.py` - theme (CSS) and components: gauges, verdict banners, radar hero, gateway pipeline, severity bar.
- `.streamlit/config.toml` - dark theme so native widgets and tables match. Needs Streamlit >= 1.40 (Material icons on buttons).
- All scan output shown in HTML components is escaped, since evidence comes from remote targets.
