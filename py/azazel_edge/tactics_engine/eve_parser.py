"""
eve_parser.py - Suricata EVE JSON 入力破損耐性
壊れたJSON行・不完全行を握りつぶし、プロセス停止禁止
"""

import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("tactics_engine.eve_parser")


@dataclass
class ParseStats:
    """解析統計"""
    total_lines: int = 0
    successful_parses: int = 0
    json_decode_fails: int = 0
    skipped_lines: int = 0


class EVEParseError(Exception):
    """EVE解析エラー（プロセス継続は保証）"""
    pass


class EVEParser:
    """Suricata EVE JSON ファイル解析（破損耐性付き）"""

    def __init__(self, max_warnings_per_session: int = 5):
        """
        Args:
            max_warnings_per_session: session内での警告数上限（過剰ログ抑制）
        """
        self.max_warnings_per_session = max_warnings_per_session
        self.warning_count = 0
        self.stats = ParseStats()

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        1行のJSONを解析

        失敗時は None を返し、プロセス停止なし

        Args:
            line: JSON行

        Returns:
            解析されたdict、または None（失敗時）
        """
        self.stats.total_lines += 1
        line = line.strip()

        # 空行スキップ
        if not line:
            self.stats.skipped_lines += 1
            return None

        try:
            obj = json.loads(line)
            self.stats.successful_parses += 1
            return obj
        except json.JSONDecodeError as e:
            self.stats.json_decode_fails += 1
            self.warning_count += 1
            if self.warning_count <= self.max_warnings_per_session:
                logger.warning(f"EVE JSON decode error (line {self.stats.total_lines}): {e}")
            elif self.warning_count == self.max_warnings_per_session + 1:
                logger.warning(f"EVE parse errors exceed {self.max_warnings_per_session}, suppressing further warnings")
            return None
        except Exception as e:
            self.stats.json_decode_fails += 1
            logger.warning(f"Unexpected EVE parse error: {e}")
            return None

    def extract_alert_features(self, eve_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        EVE オブジェクトから脅威ジャッジに必要な特徴を抽出

        不完全な場合は既定値を埋める（決定論）

        Args:
            eve_obj: 解析されたEVE dict

        Returns:
            {"suricata_sid": int, "suricata_sev": int, ...}  or None
        """
        if not isinstance(eve_obj, dict):
            return None

        features = {
            "suricata_sid": 0,
            "suricata_sev": 0,
            "suricata_signature": "",
        }

        # alert サブオブジェクト
        alert = eve_obj.get("alert", {})
        if not isinstance(alert, dict):
            return features  # 既定値で返す

        # sid / severity / signature 抽出
        if "sid" in alert:
            try:
                features["suricata_sid"] = int(alert["sid"])
            except (ValueError, TypeError):
                pass

        if "severity" in alert:
            try:
                features["suricata_sev"] = int(alert["severity"])
            except (ValueError, TypeError):
                pass

        if "signature" in alert:
            sig = alert["signature"]
            if isinstance(sig, str):
                features["suricata_signature"] = sig[:128]  # 長すぎる場合は切詰

        return features

    # Production parity: the keys returned here MUST stay byte-identical to the
    # feature dict the live agent builds at agent.py:_build_advisory (suricata_sid,
    # suricata_sev, suricata_signature, suricata_category, suricata_action,
    # target_port, protocol). The benchmark replays through this so "replay" and
    # "production" score the same alert identically. test_scorer_wiring_v1 pins it.
    SCORER_FEATURE_KEYS = (
        "suricata_sid",
        "suricata_sev",
        "suricata_signature",
        "suricata_category",
        "suricata_action",
        "target_port",
        "protocol",
    )

    def extract_scorer_features(self, eve_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Raw EVE -> the exact feature dict TacticalScorer.score consumes in production.

        Each field is defaulted independently (corruption tolerance: a malformed
        field degrades to its default, never raises). Mirrors the production
        normalizer mapping: suricata_signature <- attack_type (free text the
        producer attaches), suricata_category <- alert.classtype.
        """
        if not isinstance(eve_obj, dict):
            return None
        alert = eve_obj.get("alert")
        if not isinstance(alert, dict):
            alert = {}

        def _int(value: Any, default: int = 0) -> int:
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        # Production sets suricata_signature from norm.attack_type ONLY (agent.py
        # _build_advisory), with no classtype fallback -- mirror that exactly so replay
        # and production score an identical alert identically, not just share keys.
        attack_type = eve_obj.get("attack_type")

        return {
            "suricata_sid": _int(alert.get("sid") or alert.get("signature_id"), 0),
            "suricata_sev": _int(alert.get("severity"), 0),
            "suricata_signature": str(attack_type if isinstance(attack_type, str) else "")[:128],
            "suricata_category": str(alert.get("category") or ""),
            "suricata_action": str(alert.get("action") or eve_obj.get("action") or "allowed"),
            "target_port": _int(eve_obj.get("dest_port") or eve_obj.get("target_port"), 0),
            "protocol": str(eve_obj.get("proto") or eve_obj.get("protocol") or ""),
        }

    def compute_event_digest(self, eve_obj: Dict[str, Any]) -> str:
        """
        EVE オブジェクトのダイジェスト（完全な行のsha256ではなく、重要フィールドのみ）

        Args:
            eve_obj: 解析されたEVE dict

        Returns:
            "sha256:<hex>"
        """
        try:
            # 重要フィールドのみを抽出して辞書順JSON化
            digest_dict = {
                "timestamp": eve_obj.get("timestamp", ""),
                "alert": {
                    "sid": eve_obj.get("alert", {}).get("sid"),
                    "severity": eve_obj.get("alert", {}).get("severity"),
                    "signature": eve_obj.get("alert", {}).get("signature", ""),
                }
            }
            sorted_json = json.dumps(digest_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            hex_digest = hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()
            return f"sha256:{hex_digest}"
        except Exception as e:
            logger.warning(f"Failed to compute event digest: {e}")
            return "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    def get_stats(self) -> ParseStats:
        """解析統計を取得"""
        return self.stats

    def reset_stats(self):
        """統計をリセット"""
        self.stats = ParseStats()
        self.warning_count = 0
