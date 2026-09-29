"""
Video authenticity analyser (original vs fake) - heuristic forensic approach.

This module does not use a deep-learning model; instead it builds a weighted score from 5 forensic
indicators. The result is a probability, not proof.

Indicators
  1. Face/background sharpness consistency  (blending artefacts)
  2. Face vs background ELA ratio           (double-compression / splice)
  3. Face bounding-box jitter               (unstable face synthesis)
  4. Face brightness flicker vs scene       (frame-wise face re-rendering)
  5. Container metadata                     (missing timestamp / re-encode tools)
"""
import json
import shutil
import subprocess

import cv2
import numpy as np

_CASCADE = None


def _cascade():
    global _CASCADE
    if _CASCADE is None:
        _CASCADE = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    return _CASCADE


def _clip(x, lo=0.0, hi=1.0):
    return float(max(lo, min(hi, x)))


def _resize(frame, width=640):
    h, w = frame.shape[:2]
    if w <= width:
        return frame
    return cv2.resize(frame, (width, int(h * width / w)))


def _largest_face(gray):
    faces = _cascade().detectMultiScale(gray, 1.1, 5, minSize=(60, 60))
    if len(faces) == 0:
        return None
    return max(faces, key=lambda f: f[2] * f[3])


def _ela_map(frame, quality=90):
    ok, enc = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, quality])
    dec = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    return cv2.absdiff(frame, dec).astype(np.float32).mean(axis=2)


def extract_metadata(path):
    if not shutil.which("ffprobe"):
        return {"available": False}
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", "-show_streams", path],
            capture_output=True, text=True, timeout=20).stdout
        j = json.loads(out)
    except Exception:
        return {"available": False}
    tags = {k.lower(): str(v) for k, v in j.get("format", {}).get("tags", {}).items()}
    for s in j.get("streams", []):
        for k, v in s.get("tags", {}).items():
            tags.setdefault(k.lower(), str(v))
    return {"available": True, "tags": tags,
            "creation_time": tags.get("creation_time", ""),
            "encoder": tags.get("encoder", ""),
            "format": j.get("format", {}).get("format_name", "")}


def analyze_video(path, sample_frames=40, temporal_window=90):
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise ValueError("Could not open the video (check the format/codec).")
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    fps = float(cap.get(cv2.CAP_PROP_FPS) or 0)
    width, height = int(cap.get(3)), int(cap.get(4))
    if total <= 0:
        raise ValueError("No frames found in the video.")

    # ---------- spatial pass (frames evenly sampled) ----------
    idxs = np.unique(np.linspace(0, total - 1, num=min(sample_frames, total)).astype(int))
    sharp_ratios, ela_ratios, sampled, with_face = [], [], 0, 0
    for i in idxs:
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(i))
        ok, frame = cap.read()
        if not ok:
            continue
        sampled += 1
        frame = _resize(frame)
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        face = _largest_face(gray)
        if face is None:
            continue
        x, y, w, h = map(int, face)
        mask = np.zeros(gray.shape, bool)
        mask[y:y + h, x:x + w] = True
        if (~mask).sum() < 500:
            continue
        with_face += 1
        lap = cv2.Laplacian(gray, cv2.CV_32F) ** 2
        sharp_ratios.append(float(lap[mask].mean()) / (float(lap[~mask].mean()) + 1e-6))
        ela = _ela_map(frame)
        ela_ratios.append(float(ela[mask].mean()) / (float(ela[~mask].mean()) + 1e-6))

    # ---------- temporal pass (consecutive frames) ----------
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    centers, widths, face_b, glob_b, seen = [], [], [], [], 0
    for _ in range(temporal_window):
        ok, frame = cap.read()
        if not ok:
            break
        seen += 1
        gray = cv2.cvtColor(_resize(frame), cv2.COLOR_BGR2GRAY)
        face = _largest_face(gray)
        if face is None:
            continue
        x, y, w, h = map(int, face)
        centers.append((x + w / 2, y + h / 2))
        widths.append(w)
        face_b.append(float(gray[y:y + h, x:x + w].mean()))
        glob_b.append(float(gray.mean()))
    cap.release()

    indicators = []

    def add(name, value, score, weight, note):
        indicators.append({"indicator": name, "value": round(float(value), 3),
                           "suspicion": round(score, 2), "weight": weight, "note": note})

    if len(sharp_ratios) >= 5:
        a = np.array(sharp_ratios)
        cv = a.std() / (a.mean() + 1e-6)
        add("Face/background sharpness consistency (CV)", cv, _clip((cv - 0.35) / 0.6), 0.25,
            "In real videos face sharpness stays stable across frames; blending artefacts make it fluctuate.")
    if len(ela_ratios) >= 5:
        med = float(np.median(ela_ratios))
        dev = abs(np.log2(med + 1e-6))
        add("Face vs background ELA ratio (log2 dev)", dev, _clip((dev - 0.6) / 1.2), 0.25,
            "If the face region's compression error differs from the background, the face may have been pasted/regenerated afterwards.")
    if len(widths) >= 15:
        c = np.array(centers)
        disp = np.hypot(*np.diff(c, axis=0).T).mean() / (np.mean(widths) + 1e-6)
        add("Face bounding-box jitter", disp, _clip((disp - 0.03) / 0.10), 0.20,
            "Synthesised faces change position/size unnaturally from frame to frame.")
        fb, gb = np.diff(face_b), np.diff(glob_b)
        ratio = fb.std() / (gb.std() + 1.0)
        add("Face brightness flicker vs scene", ratio, _clip((ratio - 1.5) / 3.0), 0.15,
            "If face brightness flickers independently of the scene, the face is likely rendered separately.")

    meta = extract_metadata(path)
    if meta.get("available"):
        s = 0.0
        if not meta["creation_time"]:
            s += 0.4
        if any(k in meta["encoder"].lower() for k in ("lavf", "ffmpeg", "handbrake", "libx264")):
            s += 0.4
        add("Container metadata anomalies", s, _clip(s), 0.15,
            "Missing creation_time or a generic re-encode tool tag - a hint of editing/re-export.")

    if indicators:
        wsum = sum(i["weight"] for i in indicators)
        fake_score = 100 * sum(i["suspicion"] * i["weight"] for i in indicators) / wsum
    else:
        fake_score = None

    face_ratio = with_face / sampled if sampled else 0
    conf = "Low"
    if with_face >= 20 and face_ratio > 0.6:
        conf = "High"
    elif with_face >= 8:
        conf = "Medium"

    face_based = [i for i in indicators if not i["indicator"].startswith("Container metadata")]
    if fake_score is None or not face_based:
        # metadata alone is not decisive (every re-exported original video would be flagged)
        verdict = "Inconclusive (no usable face - metadata alone is not decisive)"
        conf = "Low"
        fake_score = None
    elif fake_score >= 60:
        verdict = "Likely Fake / Manipulated"
    elif fake_score >= 35:
        verdict = "Suspicious - manual review needed"
    else:
        verdict = "Likely Original"

    return {"verdict": verdict,
            "fake_score": None if fake_score is None else round(fake_score, 1),
            "confidence": conf,
            "stats": {"frames_total": total, "fps": round(fps, 2), "resolution": f"{width}x{height}",
                      "frames_sampled": sampled, "frames_with_face": with_face,
                      "consecutive_frames_read": seen},
            "indicators": indicators, "metadata": meta}
