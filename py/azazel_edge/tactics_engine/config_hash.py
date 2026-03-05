"""
config_hash.py - Tactics Engine の設定再現性を保証
同一 config_hash = 同一動作が期待される（ただし時刻・ランダムは除く）
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("tactics_engine.config_hash")


class ConfigHash:
    """設定ファイルの SHA256 ハッシュを計算し、再現性を担保する"""

    @staticmethod
    def compute(config_dict: Optional[Dict[str, Any]] = None, config_file: Optional[Path] = None) -> str:
        """
        config_hash を計算

        優先順位:
        1. config_file が指定され存在 → ファイルのバイト列をsha256
        2. config_dict が指定 → 整列JSON化して sha256
        3. 既定: configs/first_minute.yaml を探す

        Args:
            config_dict: 設定辞書（dict形式）
            config_file: 設定ファイルパス

        Returns:
            "sha256:<hex>" 形式の文字列
        """
        content_bytes = None

        # 1. ファイル優先
        if config_file:
            config_path = Path(config_file)
            if config_path.exists():
                try:
                    content_bytes = config_path.read_bytes()
                    logger.debug(f"config_hash: file {config_file} ({len(content_bytes)} bytes)")
                except Exception as e:
                    logger.warning(f"Failed to read config file {config_file}: {e}")

        # 2. ファイルなければ dict
        if content_bytes is None and config_dict:
            try:
                # 決定論のため、キーを辞書順で固定
                sorted_json = json.dumps(config_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                content_bytes = sorted_json.encode("utf-8")
                logger.debug(f"config_hash: dict ({len(content_bytes)} bytes)")
            except Exception as e:
                logger.warning(f"Failed to serialize config dict: {e}")

        # 3. それでもなければデフォルトファイルを探す
        if content_bytes is None:
            default_paths = [
                Path("configs/first_minute.yaml"),
                Path("/etc/azazel-edge/first_minute.yaml"),
                Path("/opt/azazel-edge/configs/first_minute.yaml"),
            ]
            for p in default_paths:
                if p.exists():
                    try:
                        content_bytes = p.read_bytes()
                        logger.debug(f"config_hash: found default {p} ({len(content_bytes)} bytes)")
                        break
                    except Exception as e:
                        logger.debug(f"Failed to read {p}: {e}")

        # 4. ファイルもなければハードコード既定値
        if content_bytes is None:
            fallback_dict = {
                "state_machine": {
                    "contain_threshold": 50,
                    "contain_exit_threshold": 30,
                    "contain_min_duration_sec": 20,
                    "decay_per_sec": 3,
                    "normal_threshold": 8,
                    "degrade_threshold": 20,
                    "suricata_cooldown_sec": 30,
                }
            }
            sorted_json = json.dumps(fallback_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            content_bytes = sorted_json.encode("utf-8")
            logger.warning(f"config_hash: using hardcoded defaults ({len(content_bytes)} bytes)")

        # SHA256 計算
        hex_digest = hashlib.sha256(content_bytes).hexdigest()
        result = f"sha256:{hex_digest}"
        logger.info(f"config_hash computed: {result}")
        return result

    @staticmethod
    def validate(config_hash: str) -> bool:
        """config_hash の形式チェック"""
        if not isinstance(config_hash, str):
            return False
        if not config_hash.startswith("sha256:"):
            return False
        hex_part = config_hash[7:]  # "sha256:" をスキップ
        return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)
