#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azazel EPD Controller for Waveshare 2.13inch e-Paper HAT (B) V4
3-color display (Black/White/Red) - 250x122 pixels

Dependencies:
  - Python 3.7+
  - Pillow (PIL)
  - waveshare_epd (for hardware control)

Usage:
  # NORMAL state
  python3 py/azazel_epd.py --state normal --ssid "AzazelNet" --signal -44 --risk-status "SAFE" --risk-level "LOW"
  
  # WARNING state
  python3 py/azazel_epd.py --state warning --msg "CHECK WEB"
  
  # DANGER state
  python3 py/azazel_epd.py --state danger --msg "REMOVE DEVICE"
  
  # STALE state
  python3 py/azazel_epd.py --state stale --msg "NO UPDATE"
  
  # Dry-run mode (preview only)
  python3 py/azazel_epd.py --state danger --msg "TEST" --dry-run

Icon files in icons/epd/:
  - wifi_3.png / wifi_2.png / wifi_1.png (signal strength)
  - wifi_notconnected.png (not connected)
  - eth.png (ethernet uplink)
  - warning.png (for WARNING state)
  - danger.png (for DANGER state)
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Tuple, Optional
from datetime import datetime, timezone

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("ERROR: Pillow is required. Install with: pip3 install pillow")
    sys.exit(1)

# Waveshare EPD library paths
WS_ROOT = "/opt/waveshare-epd/RaspberryPi_JetsonNano/python"
WS_LIB = "/opt/waveshare-epd/RaspberryPi_JetsonNano/python/lib"

# Display specifications
EPD_WIDTH = 250
EPD_HEIGHT = 122
LAST_RENDER_PATH = Path("/run/azazel-edge/epd_last_render.json")
try:
    DISPLAY_ROTATION_DEG = int(str(os.environ.get("DISPLAY_ROTATION_DEG", "180")).strip() or "180")
except ValueError:
    DISPLAY_ROTATION_DEG = 180

# Icon file names (user-replaceable in icons/epd/)
ICON_WIFI_STRONG = "wifi_3.png"      # Signal >= -60 dBm (very good)
ICON_WIFI_MEDIUM = "wifi_2.png"      # Signal >= -70 dBm (good)
ICON_WIFI_WEAK = "wifi_1.png"        # Signal >= -80 dBm (weak)
ICON_WIFI_DISCONNECTED = "wifi_notconnected.png"  # No connection
ICON_ETHERNET = "eth.png"            # Wired uplink
ICON_WARNING = "warning.png"
ICON_DANGER = "danger.png"


def check_icon_files(icon_dir: Path) -> None:
    """
    Check if required icon files exist.
    Exit with clear error message if any are missing.
    """
    required_icons = [
        ICON_WIFI_STRONG, ICON_WIFI_MEDIUM, ICON_WIFI_WEAK, ICON_WIFI_DISCONNECTED,
        ICON_ETHERNET,
        ICON_WARNING, ICON_DANGER
    ]
    missing = []
    
    for icon_name in required_icons:
        icon_path = icon_dir / icon_name
        if not icon_path.exists():
            missing.append(str(icon_path))
    
    if missing:
        print("ERROR: Required icon files are missing:")
        for path in missing:
            print(f"  - {path}")
        print("\nPlease place the following PNG files in icons/epd/ directory:")
        print(f"  - {ICON_WIFI_STRONG} (Wi-Fi icon - strong signal)")
        print(f"  - {ICON_WIFI_MEDIUM} (Wi-Fi icon - medium signal)")
        print(f"  - {ICON_WIFI_WEAK} (Wi-Fi icon - weak signal)")
        print(f"  - {ICON_WIFI_DISCONNECTED} (Wi-Fi icon - not connected)")
        print(f"  - {ICON_ETHERNET} (Ethernet icon - wired uplink)")
        print(f"  - {ICON_WARNING} (Warning icon for WARNING state)")
        print(f"  - {ICON_DANGER} (Danger icon for DANGER state)")
        sys.exit(1)


def load_font(size: int, font_name: str = "stardos") -> ImageFont.FreeTypeFont:
    """Load font. Use 'icbm' for icbmss20.ttf or 'stardos' for StardosStencilBold-9mzn.ttf."""
    # Get project root (parent of py/)
    script_dir = Path(__file__).parent
    asset_root = script_dir.parent
    
    if font_name == "icbm":
        font_path = asset_root / "fonts" / "icbmss20.ttf"
    else:  # stardos
        font_path = asset_root / "fonts" / "StardosStencilBold-9mzn.ttf"
    
    if font_path.exists():
        try:
            return ImageFont.truetype(str(font_path), size)
        except Exception as e:
            print(f"ERROR: Failed to load font {font_path}: {e}")
            sys.exit(1)
    else:
        print(f"ERROR: Font file not found: {font_path}")
        sys.exit(1)


def fit_text_single_line(
    draw: ImageDraw.ImageDraw,
    text: str,
    font_name: str,
    max_size: int,
    min_size: int,
    max_width: int,
) -> Tuple[str, ImageFont.FreeTypeFont]:
    """
    Fit text to a single line by shrinking font size, then truncating with "...".
    Returns (fitted_text, fitted_font).
    """
    raw = (text or "").strip()
    if not raw:
        raw = "-"

    for size in range(max_size, min_size - 1, -1):
        font = load_font(size, font_name)
        bbox = draw.textbbox((0, 0), raw, font=font)
        if (bbox[2] - bbox[0]) <= max_width:
            return raw, font

    font = load_font(min_size, font_name)
    trimmed = raw
    suffix = "..."
    while len(trimmed) > 1:
        candidate = f"{trimmed}{suffix}"
        bbox = draw.textbbox((0, 0), candidate, font=font)
        if (bbox[2] - bbox[0]) <= max_width:
            return candidate, font
        trimmed = trimmed[:-1]

    return suffix, font


def truncate_to_width(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    max_width: int,
) -> str:
    """Truncate text with "..." so that it fits max_width."""
    raw = (text or "").strip()
    if not raw:
        return "-"

    bbox = draw.textbbox((0, 0), raw, font=font)
    if (bbox[2] - bbox[0]) <= max_width:
        return raw

    suffix = "..."
    trimmed = raw
    while len(trimmed) > 1:
        candidate = f"{trimmed}{suffix}"
        bbox = draw.textbbox((0, 0), candidate, font=font)
        if (bbox[2] - bbox[0]) <= max_width:
            return candidate
        trimmed = trimmed[:-1]

    return suffix


def fit_text_two_lines(
    draw: ImageDraw.ImageDraw,
    text: str,
    font_name: str,
    max_size: int,
    min_size: int,
    max_width: int,
    max_height: int,
    line_gap: int = 2,
) -> Tuple[str, str, ImageFont.FreeTypeFont]:
    """
    Fit text into two centered lines by trying word-based splits with shrinking font.
    Returns (line1, line2, font). If unavoidable, line2 is truncated with "...".
    """
    raw = " ".join((text or "").strip().split())
    if not raw:
        raw = "-"
    words = raw.split(" ")

    for size in range(max_size, min_size - 1, -1):
        font = load_font(size, font_name)
        best = None
        best_width = None

        if len(words) >= 2:
            split_points = range(1, len(words))
            for i in split_points:
                line1 = " ".join(words[:i]).strip()
                line2 = " ".join(words[i:]).strip()
                if not line1 or not line2:
                    continue
                b1 = draw.textbbox((0, 0), line1, font=font)
                b2 = draw.textbbox((0, 0), line2, font=font)
                w1 = b1[2] - b1[0]
                w2 = b2[2] - b2[0]
                h1 = b1[3] - b1[1]
                h2 = b2[3] - b2[1]
                total_h = h1 + line_gap + h2
                if w1 <= max_width and w2 <= max_width and total_h <= max_height:
                    candidate_w = max(w1, w2)
                    if best is None or candidate_w < best_width:
                        best = (line1, line2, font)
                        best_width = candidate_w
        else:
            half = max(1, len(raw) // 2)
            line1 = raw[:half].strip()
            line2 = raw[half:].strip()
            b1 = draw.textbbox((0, 0), line1, font=font)
            b2 = draw.textbbox((0, 0), line2, font=font)
            w1 = b1[2] - b1[0]
            w2 = b2[2] - b2[0]
            h1 = b1[3] - b1[1]
            h2 = b2[3] - b2[1]
            total_h = h1 + line_gap + h2
            if w1 <= max_width and w2 <= max_width and total_h <= max_height:
                best = (line1, line2, font)

        if best is not None:
            return best

    font = load_font(min_size, font_name)
    if len(words) >= 2:
        split_idx = max(1, len(words) // 2)
        line1 = " ".join(words[:split_idx]).strip()
        line2 = " ".join(words[split_idx:]).strip()
    else:
        half = max(1, len(raw) // 2)
        line1 = raw[:half].strip()
        line2 = raw[half:].strip()
    line1 = truncate_to_width(draw, line1, font, max_width)
    line2 = truncate_to_width(draw, line2, font, max_width)
    return line1, line2, font


def suricata_alert_lines(msg: str) -> Optional[Tuple[str, str]]:
    """
    Return fixed 2-line label for Suricata alerts.
    Accepts slight truncation like "Suricata Ale".
    """
    normalized = " ".join((msg or "").strip().split()).lower()
    if not normalized:
        return None
    if normalized.startswith("suricata ale") or ("suricata" in normalized and "alert" in normalized):
        return ("SURICATA", "ALERT")
    return None


def normalize_warning_reason(msg: str) -> str:
    """
    Normalize WARNING reason text.
    Composite reasons that include Suricata alert are fixed to "SURICATA ALERT".
    """
    raw = " ".join((msg or "").strip().split())
    if not raw:
        return "LIMITED"

    lowered = raw.lower().replace(",", " ").replace(";", " ").replace("/", " ")
    lowered = lowered.replace("_", " ")
    tokens = [t for t in lowered.split() if t]

    if "suricata" in tokens and ("alert" in tokens or "ale" in tokens):
        return "SURICATA ALERT"
    if "suricata alert" in lowered or "suricata ale" in lowered:
        return "SURICATA ALERT"

    return raw.replace("_", " ").upper()


def should_force_two_line_alert(msg: str) -> bool:
    """Force 2-line layout for known labels that clip on one line."""
    return suricata_alert_lines(msg) is not None


def load_icon_with_transparency(icon_path: Path, max_size: int = 48) -> Image.Image:
    """
    Load PNG icon and resize while preserving transparency.
    Returns RGBA image.
    """
    try:
        icon = Image.open(icon_path).convert("RGBA")
        
        # Resize if needed
        width, height = icon.size
        if max(width, height) > max_size:
            if width > height:
                new_width = max_size
                new_height = int(height * max_size / width)
            else:
                new_height = max_size
                new_width = int(width * max_size / height)
            
            icon = icon.resize((new_width, new_height), Image.LANCZOS)
        
        return icon
    except Exception as e:
        print(f"ERROR: Failed to load icon {icon_path}: {e}")
        sys.exit(1)


def convert_to_1bit(img: Image.Image, invert: bool = False) -> Image.Image:
    """
    Convert image to 1-bit mode.
    In 1-bit mode: 0=black pixel, 255=white pixel
    For icons: dark parts of icon should be black (0), light/transparent should be white (255)
    """
    # Convert RGBA to grayscale, considering both color and alpha
    if img.mode == 'RGBA':
        # Create white background
        bg = Image.new('RGB', img.size, (255, 255, 255))
        # Composite RGBA over white background
        bg.paste(img, mask=img.split()[3])  # Use alpha as mask
        gray = bg.convert('L')
    else:
        gray = img.convert('L')
    
    # Threshold to 1-bit: dark becomes 0 (black), light becomes 255 (white)
    if invert:
        # Invert: dark becomes 255 (white), light becomes 0 (black)
        return gray.point(lambda p: 255 if p < 128 else 0, mode='1')
    else:
        # Normal: dark becomes 0 (black), light becomes 255 (white)
        return gray.point(lambda p: 0 if p < 128 else 255, mode='1')


def normalize_signal_dbm(signal: Optional[int]) -> Optional[int]:
    """
    Normalize signal strength input to dBm.
    Accepts negative dBm (preferred) or 0-100 percentage and converts to -90..-30dBm.
    """
    if signal is None:
        return None
    try:
        val = int(signal)
    except Exception:
        return None
    if 0 <= val <= 100:
        # Convert percentage back to approximate dBm (-90 to -30)
        return int(val * 0.6 - 90)
    return val


def render_normal(
    ssid: str,
    icon_dir: Path,
    signal: Optional[int] = None,
    risk_status: str = "SAFE",
    suspicion: int = 0,
    mode_label: str = "SHIELD",
    uplink_type: str = "unknown",
) -> Tuple[Image.Image, Image.Image]:
    """
    Render NORMAL state:
    - White background
    - Wi-Fi icon (top-left, black) - changes based on signal strength
    - ESSID (center, large, black) - moved from bottom
    - Risk assessment (bottom, 2 lines, small, black) - State and Suspicion score
    
    Args:
        ssid: Wi-Fi SSID ("Not Connected" if unavailable)
        icon_dir: Path to icon directory
        signal: Signal strength in dBm (e.g., -44) or 0-100% (converted) or None for disconnected
        risk_status: Risk status (e.g., "SAFE", "CHECKING", "LIMITED", "CONTAINED")
        suspicion: Suspicion score (0-100)
    """
    # Create 1-bit images: 0=black, 255=white for display; 0=no red, 255=red for red layer
    black_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)  # White background
    red_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)    # No red
    
    draw_black = ImageDraw.Draw(black_img)
    
    # Load fonts
    # Top area is 2 lines: mode (upper) + SSID (lower), as in previous layout.
    font_mode = load_font(20, "icbm")
    font_ssid = load_font(15, "stardos")
    font_evidence = load_font(20, "icbm")  # Evidence (State/Suspicion) - 20pt (icbmss20, bottom)
    
    # Select connection icon based on uplink type and Wi-Fi signal strength.
    signal_dbm = normalize_signal_dbm(signal)
    uplink = str(uplink_type or "").strip().lower()
    if uplink == "ethernet":
        connection_icon_name = ICON_ETHERNET
    elif signal_dbm is None:
        connection_icon_name = ICON_WIFI_DISCONNECTED
    elif signal_dbm >= -60:
        connection_icon_name = ICON_WIFI_STRONG
    elif signal_dbm >= -70:
        connection_icon_name = ICON_WIFI_MEDIUM
    else:
        connection_icon_name = ICON_WIFI_WEAK
    
    # Load and paste connection icon (left side, black)
    connection_icon_path = icon_dir / connection_icon_name
    connection_icon = load_icon_with_transparency(connection_icon_path, max_size=45)
    connection_icon_1bit = convert_to_1bit(connection_icon, invert=False)
    icon_x = 10
    icon_y = 8
    black_img.paste(connection_icon_1bit, (icon_x, icon_y))
    
    # Draw mode + SSID as two stacked lines in top area.
    ssid_x = icon_x + 55  # Icon width + small gap
    mode_text = (mode_label or "SHIELD").strip().upper()
    if len(mode_text) > 12:
        mode_text = mode_text[:12]
    mode_y = 8
    draw_black.text((ssid_x, mode_y), mode_text, fill=0, font=font_mode)  # 0=black

    ssid_y = 36
    draw_black.text((ssid_x, ssid_y), ssid, fill=0, font=font_ssid)  # 0=black
    
    # Draw horizontal line
    line_y = 65
    line_margin = 10
    draw_black.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=0, width=2)
    
    # Draw evidence (bottom, 2 lines) - State: STATUS, Suspicion: SCORE
    state_text = f"State: {risk_status}"
    suspicion_text = f"Suspicion: {suspicion}"
    
    # Calculate positions for centered 2-line text
    state_bbox = draw_black.textbbox((0, 0), state_text, font=font_evidence)
    state_width = state_bbox[2] - state_bbox[0]
    state_x = (EPD_WIDTH - state_width) // 2
    state_y = 70
    draw_black.text((state_x, state_y), state_text, fill=0, font=font_evidence)  # 0=black
    
    suspicion_bbox = draw_black.textbbox((0, 0), suspicion_text, font=font_evidence)
    suspicion_width = suspicion_bbox[2] - suspicion_bbox[0]
    suspicion_x = (EPD_WIDTH - suspicion_width) // 2
    suspicion_y = 100
    draw_black.text((suspicion_x, suspicion_y), suspicion_text, fill=0, font=font_evidence)  # 0=black
    
    return black_img, red_img


def render_warning(msg: str, icon_dir: Path) -> Tuple[Image.Image, Image.Image]:
    """
    Render WARNING state:
    - Black background
    - Warning icons on left and right (RED, 30pt size)
    - "WARNING" text (center, 30pt, red)
    - Horizontal line dividing screen in half (RED)
    - Bottom half: fixed 2-line text (white)
      - Line1: "CAUTION"
      - Line2: reason message
    """
    # Create layers
    black_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 0)    # Black background
    red_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)    # White/red layer
    
    draw_black = ImageDraw.Draw(black_img)
    draw_red = ImageDraw.Draw(red_img)
    
    # Load fonts - icbmss20 for WARNING state
    font_warning = load_font(35, "icbm")  # WARNING
    # Bottom evidence lines match NORMAL state's State/Suspicion typography.
    font_evidence = load_font(20, "icbm")
    msg_max_width = EPD_WIDTH - 26
    
    # Load warning icon and convert to 1-bit for RED layer (35pt size)
    warning_icon_path = icon_dir / ICON_WARNING
    warning_icon = load_icon_with_transparency(warning_icon_path, max_size=35)
    warning_icon_1bit = convert_to_1bit(warning_icon, invert=False)
    warning_icon_white = convert_to_1bit(warning_icon, invert=True)
    
    # Place warning icons in RED on left and right.
    # Knock out black background under red primitives so red is visible.
    icon_left_x = 10
    icon_right_x = EPD_WIDTH - 45  # 10px margin + 35px icon
    icon_y = 15
    black_img.paste(warning_icon_white, (icon_left_x, icon_y))
    black_img.paste(warning_icon_white, (icon_right_x, icon_y))
    red_img.paste(warning_icon_1bit, (icon_left_x, icon_y))
    red_img.paste(warning_icon_1bit, (icon_right_x, icon_y))
    
    # Draw "WARNING" text in red (center, top half)
    warning_bbox = draw_red.textbbox((0, 0), "WARNING", font=font_warning)
    warning_width = warning_bbox[2] - warning_bbox[0]
    warning_x = (EPD_WIDTH - warning_width) // 2
    warning_y = 15
    draw_black.text((warning_x, warning_y), "WARNING", fill=255, font=font_warning)  # knockout on black layer
    draw_red.text((warning_x, warning_y), "WARNING", fill=0, font=font_warning)  # 0=red pixel on red layer
    
    # Draw horizontal line dividing screen in half (y=61 for 122px height, in red)
    line_y = EPD_HEIGHT // 2
    line_margin = 10
    draw_black.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=255, width=2)  # knockout
    draw_red.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=0, width=2)
    
    # Draw bottom half as fixed 2 lines.
    # Line1 keeps NORMAL evidence size; line2 auto-shrinks to keep the full reason visible.
    caution_text = "CAUTION"
    reason_raw = normalize_warning_reason(msg)
    reason_text, font_reason = fit_text_single_line(
        draw_black,
        reason_raw,
        "icbm",
        max_size=20,
        min_size=12,
        max_width=msg_max_width,
    )

    caution_bbox = draw_black.textbbox((0, 0), caution_text, font=font_evidence)
    caution_width = caution_bbox[2] - caution_bbox[0]
    caution_x = (EPD_WIDTH - caution_width) // 2
    caution_y = 70
    draw_black.text((caution_x, caution_y), caution_text, fill=255, font=font_evidence)  # 255=white

    reason_bbox = draw_black.textbbox((0, 0), reason_text, font=font_reason)
    reason_width = reason_bbox[2] - reason_bbox[0]
    reason_x = (EPD_WIDTH - reason_width) // 2
    reason_y = 100
    draw_black.text((reason_x, reason_y), reason_text, fill=255, font=font_reason)  # 255=white
    
    return black_img, red_img


def render_danger(msg: str, icon_dir: Path) -> Tuple[Image.Image, Image.Image]:
    """
    Render DANGER state:
    - Black background
    - Warning icons on left and right (RED, 35pt size)
    - "DANGER" text (center, 35pt, red)
    - Horizontal line dividing screen in half (RED)
    - Message (bottom half, white)
    """
    # Create layers
    black_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 0)    # Black background
    red_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)    # White/red layer
    
    draw_black = ImageDraw.Draw(black_img)
    draw_red = ImageDraw.Draw(red_img)
    
    # Load fonts - icbmss20 for DANGER state
    font_danger = load_font(35, "icbm")
    # Message font is adaptive; SURICATA ALERT is forced to 2-line to avoid clipping.
    msg_max_width = EPD_WIDTH - 26
    
    # Load warning icon
    warning_icon_path = icon_dir / ICON_WARNING
    warning_icon = load_icon_with_transparency(warning_icon_path, max_size=40)
    warning_icon_1bit = convert_to_1bit(warning_icon, invert=False)
    warning_icon_white = convert_to_1bit(warning_icon, invert=True)
    
    # Place warning icons in RED and knock out black below.
    icon_left_x = 10
    icon_right_x = EPD_WIDTH - 50  # 10px margin + 40px icon
    icon_y = 15
    black_img.paste(warning_icon_white, (icon_left_x, icon_y))
    black_img.paste(warning_icon_white, (icon_right_x, icon_y))
    red_img.paste(warning_icon_1bit, (icon_left_x, icon_y))
    red_img.paste(warning_icon_1bit, (icon_right_x, icon_y))
    
    # Draw "DANGER" text in red (center, top half, 35pt)
    danger_bbox = draw_red.textbbox((0, 0), "DANGER", font=font_danger)
    danger_width = danger_bbox[2] - danger_bbox[0]
    danger_x = (EPD_WIDTH - danger_width) // 2
    danger_y = 15
    draw_black.text((danger_x, danger_y), "DANGER", fill=255, font=font_danger)  # knockout
    draw_red.text((danger_x, danger_y), "DANGER", fill=0, font=font_danger)      # red
    
    # Draw horizontal line dividing screen in half (y=61 for 122px height)
    line_y = EPD_HEIGHT // 2
    line_margin = 10
    draw_black.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=255, width=2)  # knockout
    draw_red.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=0, width=2)
    
    # Draw message (bottom half, centered, white)
    bottom_top = line_y + 2
    bottom_height = EPD_HEIGHT - bottom_top
    if should_force_two_line_alert(msg):
        fixed = suricata_alert_lines(msg)
        if fixed is not None:
            line1, line2 = fixed
            font_message = load_font(22, "icbm")
        else:
            line1, line2, font_message = fit_text_two_lines(
                draw_black,
                msg,
                "icbm",
                max_size=22,
                min_size=12,
                max_width=msg_max_width,
                max_height=bottom_height - 2,
                line_gap=2,
            )
        b1 = draw_black.textbbox((0, 0), line1, font=font_message)
        b2 = draw_black.textbbox((0, 0), line2, font=font_message)
        w1, h1 = b1[2] - b1[0], b1[3] - b1[1]
        w2, h2 = b2[2] - b2[0], b2[3] - b2[1]
        total_h = h1 + 2 + h2
        y1 = bottom_top + max(0, (bottom_height - total_h) // 2)
        y2 = y1 + h1 + 2
        x1 = (EPD_WIDTH - w1) // 2
        x2 = (EPD_WIDTH - w2) // 2
        draw_black.text((x1, y1), line1, fill=255, font=font_message)  # 255=white
        draw_black.text((x2, y2), line2, fill=255, font=font_message)  # 255=white
    else:
        msg_text, font_message = fit_text_single_line(
            draw_black, msg, "icbm", max_size=25, min_size=14, max_width=msg_max_width
        )
        msg_bbox = draw_black.textbbox((0, 0), msg_text, font=font_message)
        msg_width = msg_bbox[2] - msg_bbox[0]
        msg_height = msg_bbox[3] - msg_bbox[1]
        msg_x = (EPD_WIDTH - msg_width) // 2
        msg_y = bottom_top + max(0, (bottom_height - msg_height) // 2)
        draw_black.text((msg_x, msg_y), msg_text, fill=255, font=font_message)  # 255=white
    
    return black_img, red_img


def render_stale(msg: str, icon_dir: Path) -> Tuple[Image.Image, Image.Image]:
    """
    Render STALE state:
    - White background
    - "STALE" text in upper half (black, icbmss20, 35pt)
    - Horizontal line dividing screen in half
    - "NO UPDATE" and "CHECK WEB PORTAL" in lower half (black, icbmss20, 20pt, 2 lines)
    """
    # Create layers
    black_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)  # White background
    red_img = Image.new('1', (EPD_WIDTH, EPD_HEIGHT), 255)    # No red
    
    draw_black = ImageDraw.Draw(black_img)
    
    # Load fonts - icbmss20 for STALE state
    font_stale = load_font(35, "icbm")    # STALE
    font_message = load_font(20, "icbm")  # Messages
    
    # Draw "STALE" text in upper half (black, centered)
    stale_bbox = draw_black.textbbox((0, 0), "STALE", font=font_stale)
    stale_width = stale_bbox[2] - stale_bbox[0]
    stale_x = (EPD_WIDTH - stale_width) // 2
    stale_y = 15
    draw_black.text((stale_x, stale_y), "STALE", fill=0, font=font_stale)  # 0=black
    
    # Draw horizontal line dividing screen in half (y=61 for 122px height)
    line_y = EPD_HEIGHT // 2
    line_margin = 10
    draw_black.line([(line_margin, line_y), (EPD_WIDTH - line_margin, line_y)], fill=0, width=2)
    
    # Draw "NO UPDATE" in lower half, first line (black, centered)
    msg1_text = "NO UPDATE"
    msg1_bbox = draw_black.textbbox((0, 0), msg1_text, font=font_message)
    msg1_width = msg1_bbox[2] - msg1_bbox[0]
    msg1_x = (EPD_WIDTH - msg1_width) // 2
    msg1_y = line_y + 10
    draw_black.text((msg1_x, msg1_y), msg1_text, fill=0, font=font_message)  # 0=black
    
    # Draw "CHECK WEB PORTAL" in lower half, second line (black, centered)
    msg2_text = "CHECK WEB PORTAL"
    msg2_bbox = draw_black.textbbox((0, 0), msg2_text, font=font_message)
    msg2_width = msg2_bbox[2] - msg2_bbox[0]
    msg2_x = (EPD_WIDTH - msg2_width) // 2
    msg2_y = msg1_y + 25
    draw_black.text((msg2_x, msg2_y), msg2_text, fill=0, font=font_message)  # 0=black
    
    return black_img, red_img


def save_preview(black_img: Image.Image, red_img: Image.Image, state: str) -> None:
    """
    Save preview images for debugging.
    Generates:
    - Black layer preview
    - Red layer preview
    - Composite preview (visual representation)
    """
    base = f"/tmp/azazel_epd_preview_{state}"
    
    # Save black layer
    black_img.save(f"{base}_black.png")
    
    # Save red layer
    red_img.save(f"{base}_red.png")
    
    # Create composite RGB image for visual preview
    composite = Image.new('RGB', (EPD_WIDTH, EPD_HEIGHT), (255, 255, 255))  # White bg
    
    # Convert 1-bit to RGB arrays
    black_pixels = black_img.load()
    red_pixels = red_img.load()
    composite_pixels = composite.load()
    
    for y in range(EPD_HEIGHT):
        for x in range(EPD_WIDTH):
            # In 1-bit mode: 0=black/red, 255=white/off
            is_black = black_pixels[x, y] == 0
            is_red = red_pixels[x, y] == 0
            
            if is_black:
                composite_pixels[x, y] = (0, 0, 0)  # Black
            elif is_red:
                composite_pixels[x, y] = (255, 0, 0)  # Red
            else:
                composite_pixels[x, y] = (255, 255, 255)  # White
    
    composite.save(f"{base}_composite.png")
    
    print("✓ Preview saved:")
    print(f"  Black layer: {base}_black.png")
    print(f"  Red layer:   {base}_red.png")
    print(f"  Composite:   {base}_composite.png")


def apply_display_rotation(black_img: Image.Image, red_img: Image.Image) -> tuple[Image.Image, Image.Image]:
    """Apply panel orientation compensation before preview/display."""
    if DISPLAY_ROTATION_DEG == 180:
        return (
            black_img.transpose(Image.ROTATE_180),
            red_img.transpose(Image.ROTATE_180),
        )
    return black_img, red_img


def display_to_epd(black_img: Image.Image, red_img: Image.Image) -> None:
    """
    Display images to actual EPD hardware.
    Uses Waveshare epd2in13b_V4 driver.
    """
    # Add Waveshare library to path
    for p in (WS_ROOT, WS_LIB):
        if p not in sys.path:
            sys.path.append(p)

    epd = None
    try:
        from waveshare_epd import epd2in13b_V4
        epd = epd2in13b_V4.EPD()
    except ImportError as e:
        print("ERROR: Waveshare EPD library not found.")
        print(f"Details: {e}")
        print("\nMake sure the library is installed at:")
        print(f"  {WS_LIB}")
        print("\nOr use --dry-run to test without hardware.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to initialize EPD: {e}")
        sys.exit(1)

    try:
        print("Initializing EPD...")
        epd.init()

        print("Sending image data...")
        # Convert 1-bit images to buffers
        black_buffer = epd.getbuffer(black_img)
        red_buffer = epd.getbuffer(red_img)

        # Display both layers (skip Clear() to save time)
        epd.display(black_buffer, red_buffer)

        print("Putting EPD to sleep...")
        epd.sleep()

        print("✓ Display updated successfully")

    except Exception as e:
        print(f"ERROR: EPD operation failed: {e}")
        import traceback
        traceback.print_exc()
        if epd:
            try:
                epd.sleep()
            except Exception:
                pass
        sys.exit(1)


def write_last_render(render_spec: dict) -> None:
    """Persist last successful render spec for redraw de-duplication."""
    try:
        LAST_RENDER_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "render": render_spec,
        }
        tmp = LAST_RENDER_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(tmp, LAST_RENDER_PATH)
    except Exception:
        # Non-fatal: rendering should succeed even if state persistence fails.
        pass


def main():
    parser = argparse.ArgumentParser(
        description='Azazel EPD Controller for Waveshare 2.13" e-Paper HAT (B) V4',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --state normal --ssid "AzazelNet" --risk-status "SAFE" --suspicion 0
  %(prog)s --state normal --ssid "MyWiFi" --signal -55 --risk-status "LIMITED" --suspicion 25
  %(prog)s --state warning --msg "CHECK WEB"
  %(prog)s --state danger --msg "REMOVE DEVICE"
  %(prog)s --state stale --msg "NO UPDATE"
  %(prog)s --state danger --msg "TEST" --dry-run
        """
    )
    
    parser.add_argument('--state', required=True, 
                       choices=['normal', 'warning', 'danger', 'stale'],
                       help='Display state')
    parser.add_argument('--ssid', help='Wi-Fi SSID (for normal state)')
    parser.add_argument('--mode-label', default='SHIELD', help='Gateway mode label shown above SSID (for normal state)')
    parser.add_argument('--signal', type=int, help='Wi-Fi signal strength in dBm (negative, e.g., -55) or 0-100%')
    parser.add_argument('--uplink-type', default='unknown', help='Uplink type for icon selection: wifi, ethernet, other')
    parser.add_argument('--risk-status', default='SAFE', help='Risk status (for normal state): SAFE, CHECKING, LIMITED, CONTAINED')
    parser.add_argument('--suspicion', type=int, default=0, help='Suspicion score (for normal state, 0-100)')
    parser.add_argument('--msg', help='Message (for warning/danger/stale states)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Generate preview only, do not update EPD')
    
    args = parser.parse_args()
    
    # Get icon directory: icons/epd/ relative to project root
    script_dir = Path(__file__).parent
    icon_dir = script_dir.parent / "icons" / "epd"
    
    # Check icon files exist
    check_icon_files(icon_dir)
    
    # Validate arguments
    if args.state == 'normal':
        if not args.ssid:
            parser.error("--ssid is required for normal state")
        # Ensure suspicion is in valid range
        if args.suspicion < 0 or args.suspicion > 100:
            parser.error("--suspicion must be between 0 and 100")
    else:
        if not args.msg:
            parser.error(f"--msg is required for {args.state} state")
    
    # Render appropriate state
    print(f"Rendering {args.state.upper()} state...")
    render_spec: dict = {"state": args.state}
    
    if args.state == 'normal':
        black_img, red_img = render_normal(
            args.ssid,
            icon_dir,
            args.signal,
            args.risk_status,
            args.suspicion,
            args.mode_label,
            args.uplink_type,
        )
        render_spec.update(
            {
                "mode_label": str(args.mode_label or "").strip().upper(),
                "ssid": str(args.ssid or ""),
                "risk_status": str(args.risk_status or "").strip().upper(),
                "suspicion": int(args.suspicion),
                "signal": args.signal if args.signal is not None else None,
                "uplink_type": str(args.uplink_type or "").strip().lower() or "unknown",
            }
        )
    elif args.state == 'warning':
        black_img, red_img = render_warning(args.msg, icon_dir)
        render_spec["msg"] = str(args.msg or "")
    elif args.state == 'danger':
        black_img, red_img = render_danger(args.msg, icon_dir)
        render_spec["msg"] = str(args.msg or "")
    elif args.state == 'stale':
        black_img, red_img = render_stale(args.msg, icon_dir)
        render_spec["msg"] = str(args.msg or "")
    
    # Output
    black_img, red_img = apply_display_rotation(black_img, red_img)
    if args.dry_run:
        save_preview(black_img, red_img, args.state)
    else:
        display_to_epd(black_img, red_img)
        write_last_render(render_spec)


if __name__ == '__main__':
    main()
