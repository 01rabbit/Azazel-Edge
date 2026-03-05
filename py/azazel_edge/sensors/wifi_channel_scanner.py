#!/usr/bin/env python3
"""
WiFi Channel Scanner - 周囲のAPをスキャンしてチャンネル混雑度を測定
"""
import re
import subprocess
from typing import Dict, List, Optional, Tuple


def scan_wifi_channels(interface: str = "wlan0") -> Dict[str, object]:
    """
    WiFiチャンネルをスキャンして混雑度を計算
    
    Returns:
        {
            "current_channel": 6,
            "congestion_level": "high",  # low, medium, high, critical
            "ap_count": 8,
            "nearby_aps": [...],
            "recommended_channel": 149,
            "scan_success": True
        }
    """
    result = {
        "current_channel": -1,
        "congestion_level": "unknown",
        "ap_count": 0,
        "nearby_aps": [],
        "recommended_channel": -1,
        "scan_success": False,
        "channel_usage": {},  # {channel_num: ap_count}
    }
    
    try:
        # iw scanを実行
        cmd = ["iw", "dev", interface, "scan"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if proc.returncode != 0:
            return result
        
        # 結果をパース
        aps = _parse_scan_output(proc.stdout)
        result["nearby_aps"] = aps
        result["ap_count"] = len(aps)
        result["scan_success"] = True
        
        # チャンネル使用状況を集計
        channel_usage = {}
        for ap in aps:
            ch = ap.get("channel", -1)
            if ch > 0:
                channel_usage[ch] = channel_usage.get(ch, 0) + 1
        
        result["channel_usage"] = channel_usage
        
        # 現在接続中のチャンネルを取得（iwコマンドで）
        current_ch = _get_current_channel(interface)
        result["current_channel"] = current_ch
        
        # 現在のチャンネルの混雑度を計算
        if current_ch > 0:
            congestion = _calculate_congestion(current_ch, channel_usage)
            result["congestion_level"] = congestion
        
        # 最適なチャンネルを推奨
        recommended = _recommend_channel(channel_usage, current_ch)
        result["recommended_channel"] = recommended
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _parse_scan_output(output: str) -> List[Dict[str, object]]:
    """iw scan出力をパース"""
    aps = []
    current_ap = {}
    
    for line in output.split("\n"):
        line = line.strip()
        
        # 新しいAP
        if line.startswith("BSS"):
            if current_ap:
                aps.append(current_ap)
            bssid_match = re.search(r"BSS ([0-9a-f:]+)", line)
            current_ap = {
                "bssid": bssid_match.group(1) if bssid_match else "-",
                "ssid": "-",
                "channel": -1,
                "signal": -100,
                "frequency": 0,
            }
        
        # SSID
        elif line.startswith("SSID:"):
            current_ap["ssid"] = line.split("SSID:", 1)[1].strip() or "(hidden)"
        
        # 周波数（チャンネル計算に使用）
        elif "freq:" in line:
            freq_match = re.search(r"freq: (\d+)", line)
            if freq_match:
                freq = int(freq_match.group(1))
                current_ap["frequency"] = freq
                current_ap["channel"] = _freq_to_channel(freq)
        
        # 信号強度
        elif "signal:" in line:
            sig_match = re.search(r"signal: ([-\d.]+)", line)
            if sig_match:
                current_ap["signal"] = float(sig_match.group(1))
    
    if current_ap:
        aps.append(current_ap)
    
    return aps


def _freq_to_channel(freq: int) -> int:
    """周波数からチャンネル番号に変換"""
    # 2.4GHz
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    
    # 5GHz
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    
    return -1


def _get_current_channel(interface: str) -> int:
    """現在接続中のチャンネルを取得"""
    try:
        cmd = ["iw", "dev", interface, "info"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if proc.returncode == 0:
            for line in proc.stdout.split("\n"):
                if "channel" in line.lower():
                    ch_match = re.search(r"channel (\d+)", line)
                    if ch_match:
                        return int(ch_match.group(1))
    except Exception:
        pass
    
    return -1


def _calculate_congestion(current_ch: int, channel_usage: Dict[int, int]) -> str:
    """混雑度を計算"""
    # 現在のチャンネル + 隣接チャンネルのAP数を合計
    adjacent_channels = []
    
    # 2.4GHzの場合、±2チャンネルが干渉する
    if 1 <= current_ch <= 14:
        adjacent_channels = [current_ch - 2, current_ch - 1, current_ch, current_ch + 1, current_ch + 2]
        adjacent_channels = [ch for ch in adjacent_channels if 1 <= ch <= 14]
    # 5GHzの場合、隣接チャンネルの影響は少ない
    else:
        adjacent_channels = [current_ch]
    
    total_aps = sum(channel_usage.get(ch, 0) for ch in adjacent_channels)
    
    # 混雑度の判定
    if total_aps == 0:
        return "none"
    elif total_aps <= 2:
        return "low"
    elif total_aps <= 5:
        return "medium"
    elif total_aps <= 10:
        return "high"
    else:
        return "critical"


def _recommend_channel(channel_usage: Dict[int, int], current_ch: int) -> int:
    """最適なチャンネルを推奨"""
    # 5GHz優先チャンネルリスト（DFS除く）
    recommended_5g = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    
    # 2.4GHz推奨チャンネル（干渉が少ない1, 6, 11）
    recommended_24g = [1, 6, 11]
    
    # 全推奨チャンネルをチェック
    all_recommended = recommended_5g + recommended_24g
    
    # 最も空いているチャンネルを探す
    best_ch = current_ch
    min_aps = channel_usage.get(current_ch, 999)
    
    for ch in all_recommended:
        ap_count = channel_usage.get(ch, 0)
        if ap_count < min_aps:
            min_aps = ap_count
            best_ch = ch
    
    return best_ch


if __name__ == "__main__":
    # テスト実行
    result = scan_wifi_channels("wlan0")
    print(f"Scan Success: {result['scan_success']}")
    print(f"Current Channel: {result['current_channel']}")
    print(f"Congestion: {result['congestion_level']}")
    print(f"Nearby APs: {result['ap_count']}")
    print(f"Recommended Channel: {result['recommended_channel']}")
    print(f"Channel Usage: {result['channel_usage']}")
