#!/usr/bin/env python3
"""
Network Analytics - パケットロス、DNS応答時間、累計統計、ブロックログ分析
"""
import re
import subprocess
import time
from collections import Counter, deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class NetworkAnalytics:
    """ネットワーク解析クラス（状態保持）"""
    
    def __init__(self):
        self.ping_history = deque(maxlen=10)  # 過去10回のping結果
        self.dns_history = deque(maxlen=20)  # 過去20回のDNSクエリ時間
        self.state_transitions = deque(maxlen=20)  # 状態遷移履歴
        self.blocked_domains = Counter()  # ブロックされたドメイン
        
    def measure_packet_loss(self, target: str = "8.8.8.8", count: int = 5) -> Dict[str, object]:
        """パケットロス率を測定"""
        result = {
            "loss_percent": 0.0,
            "avg_rtt_ms": 0.0,
            "min_rtt_ms": 0.0,
            "max_rtt_ms": 0.0,
            "success": False,
        }
        
        try:
            cmd = ["ping", "-c", str(count), "-W", "1", target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=count + 2)
            
            if proc.returncode == 0 or "packet loss" in proc.stdout:
                # パケットロス率を抽出
                loss_match = re.search(r"(\d+)% packet loss", proc.stdout)
                if loss_match:
                    result["loss_percent"] = float(loss_match.group(1))
                
                # RTT統計を抽出
                rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)", proc.stdout)
                if rtt_match:
                    result["min_rtt_ms"] = float(rtt_match.group(1))
                    result["avg_rtt_ms"] = float(rtt_match.group(2))
                    result["max_rtt_ms"] = float(rtt_match.group(3))
                
                result["success"] = True
                
                # 履歴に追加
                self.ping_history.append({
                    "timestamp": time.time(),
                    "loss_percent": result["loss_percent"],
                    "avg_rtt_ms": result["avg_rtt_ms"],
                })
        except Exception:
            pass
        
        return result
    
    def get_ping_trend(self) -> List[float]:
        """Ping RTTの推移を取得（スパークライン用）"""
        return [p["avg_rtt_ms"] for p in self.ping_history if p.get("avg_rtt_ms", 0) > 0]
    
    def get_packet_loss_trend(self) -> List[float]:
        """パケットロス率の推移を取得"""
        return [p["loss_percent"] for p in self.ping_history]
    
    def measure_dns_response_time(self, domain: str = "google.com") -> Optional[float]:
        """DNS応答時間を測定（ms）"""
        try:
            start = time.time()
            cmd = ["dig", "+short", domain, "@127.0.0.1"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            elapsed = (time.time() - start) * 1000  # ms
            
            if proc.returncode == 0 and proc.stdout.strip():
                self.dns_history.append({
                    "timestamp": time.time(),
                    "response_ms": elapsed,
                    "domain": domain,
                })
                return round(elapsed, 1)
        except Exception:
            pass
        return None
    
    def get_dns_stats(self) -> Dict[str, object]:
        """DNS統計を取得"""
        if not self.dns_history:
            return {"avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "cache_hit_rate": 0}
        
        times = [d["response_ms"] for d in self.dns_history]
        
        # キャッシュヒット率（5ms以下を判定）
        cache_hits = sum(1 for t in times if t < 5.0)
        cache_hit_rate = int((cache_hits / len(times)) * 100)
        
        return {
            "avg_ms": round(sum(times) / len(times), 1),
            "min_ms": round(min(times), 1),
            "max_ms": round(max(times), 1),
            "cache_hit_rate": cache_hit_rate,
            "timeouts": 0,  # TODO: タイムアウト検出
        }
    
    def add_state_transition(self, from_state: str, to_state: str, duration_sec: int):
        """状態遷移を記録"""
        self.state_transitions.append({
            "timestamp": time.time(),
            "from": from_state,
            "to": to_state,
            "duration_sec": duration_sec,
        })
    
    def get_state_timeline(self) -> str:
        """状態遷移タイムラインを文字列で取得"""
        if not self.state_transitions:
            return "No transitions yet"
        
        timeline = []
        for t in list(self.state_transitions)[-5:]:  # 最新5件
            duration_min = t["duration_sec"] // 60
            timeline.append(f"{t['from']}({duration_min}m)")
        
        # 現在の状態を追加
        if self.state_transitions:
            last = self.state_transitions[-1]
            timeline.append(f"{last['to']}(now)")
        
        return " → ".join(timeline)
    
    def add_blocked_domain(self, domain: str):
        """ブロックされたドメインを記録"""
        self.blocked_domains[domain] += 1
    
    def get_top_blocked(self, limit: int = 5) -> List[Tuple[str, int]]:
        """ブロック数トップNを取得"""
        return self.blocked_domains.most_common(limit)
    
    def get_traffic_cumulative(
        self,
        interface: str,
        start_stats: Optional[Dict[str, int]] = None
    ) -> Dict[str, object]:
        """累計トラフィック統計を取得"""
        from .system_metrics import get_network_stats
        
        current = get_network_stats(interface)
        
        if start_stats is None:
            start_stats = current
        
        rx_mb = (current["rx_bytes"] - start_stats.get("rx_bytes", 0)) / (1024 * 1024)
        tx_mb = (current["tx_bytes"] - start_stats.get("tx_bytes", 0)) / (1024 * 1024)
        rx_pkts = current["rx_packets"] - start_stats.get("rx_packets", 0)
        tx_pkts = current["tx_packets"] - start_stats.get("tx_packets", 0)
        
        return {
            "download_mb": round(rx_mb, 1),
            "upload_mb": round(tx_mb, 1),
            "total_mb": round(rx_mb + tx_mb, 1),
            "packets": rx_pkts + tx_pkts,
        }


# グローバルインスタンス（状態保持）
_analytics = NetworkAnalytics()


def get_analytics() -> NetworkAnalytics:
    """シングルトンインスタンスを取得"""
    return _analytics


if __name__ == "__main__":
    # テスト実行
    analytics = get_analytics()
    
    print("=== Packet Loss Test ===")
    result = analytics.measure_packet_loss("8.8.8.8", 3)
    print(f"Loss: {result['loss_percent']}%")
    print(f"RTT: {result['avg_rtt_ms']}ms")
    
    print("\n=== DNS Test ===")
    dns_time = analytics.measure_dns_response_time("google.com")
    print(f"DNS Response: {dns_time}ms")
    dns_stats = analytics.get_dns_stats()
    print(f"DNS Stats: {dns_stats}")
    
    print("\n=== State Timeline ===")
    analytics.add_state_transition("PROBE", "NORMAL", 120)
    analytics.add_state_transition("NORMAL", "DEGRADED", 300)
    print(analytics.get_state_timeline())
    
    print("\n=== Blocked Domains ===")
    analytics.add_blocked_domain("malware.example")
    analytics.add_blocked_domain("malware.example")
    analytics.add_blocked_domain("ads.tracker")
    print(analytics.get_top_blocked(5))
