#!/usr/bin/env python3
"""
System Metrics Collector - CPU、メモリ、温度、ネットワークスループットを収集
"""
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Tuple


def get_cpu_usage() -> float:
    """CPU使用率を取得（0-100）"""
    try:
        # /proc/statから計算
        with open("/proc/stat") as f:
            line = f.readline()
            values = [int(x) for x in line.split()[1:]]
            total = sum(values)
            idle = values[3]  # idle time
            
            # 前回の値と比較するため、簡易的に現在値のみ返す
            # より正確にはグローバル変数で前回値を保持すべき
            if total > 0:
                return round((1 - idle / total) * 100, 1)
    except Exception:
        pass
    return 0.0


def get_memory_usage() -> Dict[str, int]:
    """メモリ使用状況を取得（MB単位）"""
    result = {"total_mb": 0, "used_mb": 0, "available_mb": 0, "percent": 0}
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
            mem_info = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = int(parts[1].strip().split()[0])  # KB
                    mem_info[key] = value
            
            total = mem_info.get("MemTotal", 0)
            available = mem_info.get("MemAvailable", 0)
            used = total - available
            
            result["total_mb"] = total // 1024
            result["used_mb"] = used // 1024
            result["available_mb"] = available // 1024
            result["percent"] = int((used / total * 100)) if total > 0 else 0
    except Exception:
        pass
    return result


def get_cpu_temperature() -> Optional[float]:
    """CPU温度を取得（℃）"""
    try:
        # Raspberry Pi の温度
        temp_path = Path("/sys/class/thermal/thermal_zone0/temp")
        if temp_path.exists():
            temp = int(temp_path.read_text().strip())
            return round(temp / 1000.0, 1)  # milli-degrees to degrees
    except Exception:
        pass
    return None


def get_network_stats(interface: str) -> Dict[str, int]:
    """ネットワーク統計を取得（bytes）"""
    result = {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0}
    try:
        rx_path = Path(f"/sys/class/net/{interface}/statistics/rx_bytes")
        tx_path = Path(f"/sys/class/net/{interface}/statistics/tx_bytes")
        rx_pkts_path = Path(f"/sys/class/net/{interface}/statistics/rx_packets")
        tx_pkts_path = Path(f"/sys/class/net/{interface}/statistics/tx_packets")
        
        if rx_path.exists():
            result["rx_bytes"] = int(rx_path.read_text().strip())
        if tx_path.exists():
            result["tx_bytes"] = int(tx_path.read_text().strip())
        if rx_pkts_path.exists():
            result["rx_packets"] = int(rx_pkts_path.read_text().strip())
        if tx_pkts_path.exists():
            result["tx_packets"] = int(tx_pkts_path.read_text().strip())
    except Exception:
        pass
    return result


def get_link_speed_mbps(interface: str) -> Optional[int]:
    """リンク速度を取得（Mbps）。未知または unsupported の場合は None。"""
    try:
        path = Path(f"/sys/class/net/{interface}/speed")
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        speed = int(raw)
        if speed <= 0:
            return None
        return speed
    except Exception:
        return None


def calculate_throughput(
    prev_stats: Dict[str, int],
    curr_stats: Dict[str, int],
    interval_sec: float
) -> Dict[str, float]:
    """スループットを計算（Mbps）"""
    result = {"download_mbps": 0.0, "upload_mbps": 0.0}
    
    if interval_sec <= 0:
        return result
    
    try:
        rx_diff = curr_stats["rx_bytes"] - prev_stats["rx_bytes"]
        tx_diff = curr_stats["tx_bytes"] - prev_stats["tx_bytes"]
        
        # bytes -> bits -> Mbps
        result["download_mbps"] = round((rx_diff * 8) / (interval_sec * 1_000_000), 2)
        result["upload_mbps"] = round((tx_diff * 8) / (interval_sec * 1_000_000), 2)
    except Exception:
        pass
    
    return result


def get_wifi_uptime(interface: str) -> Optional[int]:
    """WiFi接続時間を取得（秒）"""
    try:
        # iwコマンドでconnected time確認
        result = subprocess.run(
            ["iw", "dev", interface, "link"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # "Connected to ... (on wlan0)" が見つかれば接続中
            if "Connected to" in result.stdout:
                # より詳細な情報は/sys/class/net/wlan0/carrier_up_countなどから
                # 簡易的に接続中かどうかだけ判定
                # 実際のuptimeは別途追跡が必要
                return 0  # TODO: 実装が必要
    except Exception:
        pass
    return None


def get_suricata_alerts(log_path: Path, max_lines: int = 100) -> Dict[str, int]:
    """Suricataアラート統計を取得"""
    result = {"critical": 0, "warning": 0, "info": 0, "total": 0}
    
    if not log_path.exists():
        return result
    
    try:
        # fast.logから最新行を読み取り
        with open(log_path, "r") as f:
            lines = f.readlines()[-max_lines:]
        
        for line in lines:
            # [Priority: 1] -> critical
            # [Priority: 2-3] -> warning
            # [Priority: 4+] -> info
            priority_match = re.search(r"\[Priority: (\d+)\]", line)
            if priority_match:
                priority = int(priority_match.group(1))
                result["total"] += 1
                
                if priority == 1:
                    result["critical"] += 1
                elif priority in (2, 3):
                    result["warning"] += 1
                else:
                    result["info"] += 1
    except Exception:
        pass
    
    return result


def collect_all_metrics(
    up_interface: str = "wlan0",
    down_interface: str = "usb0",
    suricata_log: str = "/var/log/suricata/fast.log"
) -> Dict[str, object]:
    """全てのメトリクスを一度に収集"""
    return {
        "cpu_percent": get_cpu_usage(),
        "memory": get_memory_usage(),
        "temperature_c": get_cpu_temperature(),
        "network_up": get_network_stats(up_interface),
        "network_down": get_network_stats(down_interface),
        "suricata_alerts": get_suricata_alerts(Path(suricata_log)),
        "timestamp": time.time(),
    }


if __name__ == "__main__":
    # テスト実行
    metrics = collect_all_metrics()
    print("CPU:", metrics["cpu_percent"], "%")
    print("Memory:", metrics["memory"])
    print("Temperature:", metrics["temperature_c"], "°C")
    print("Network (wlan0):", metrics["network_up"])
    print("Network (usb0):", metrics["network_down"])
    print("Suricata Alerts:", metrics["suricata_alerts"])
