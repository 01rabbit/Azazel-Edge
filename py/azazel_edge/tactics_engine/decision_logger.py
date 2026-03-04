"""
decision_logger.py - DecisionExplanation JSONL ロギング
意思決定をJSON形式で永続化し、機械可読な監査ログとする
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import asdict, dataclass, field

logger = logging.getLogger("tactics_engine.decision_logger")


@dataclass
class StateSnapshot:
    """状態スナップショット"""
    state: str
    user_state: str
    suspicion: float
    risk_score: int


@dataclass
class InputSnapshot:
    """入力スナップショット"""
    source: str  # "suricata" | "wifi" | "internal"
    event_digest: str  # sha256:...
    event_min: Optional[Dict[str, Any]] = None  # 最小限の生データ


@dataclass
class ScoreDelta:
    """suspicion の変化量"""
    suspicion_add: float = 0.0
    suspicion_decay: float = 0.0


@dataclass
class ChosenAction:
    """選択された遷移または行動"""
    action_type: str  # "transition" | "action" | "constraint"
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionRecord:
    """1つの意思決定ターン"""
    ts: str  # ISO8601
    decision_id: str  # UUID
    engine: Dict[str, str]

    config_hash: str

    inputs_snapshot: InputSnapshot
    features: Dict[str, Any]

    state_before: StateSnapshot
    score_delta: ScoreDelta
    constraints_triggered: List[str]  # ["cooldown_hit", "min_duration_active", ...]
    chosen: List[ChosenAction]
    state_after: StateSnapshot

    parse_errors: Dict[str, int]  # {"json_decode_fail": 0, "skipped_lines": 0}

    def to_json(self) -> str:
        """JSONL行に変換（改行なし）"""
        d = {
            "ts": self.ts,
            "decision_id": self.decision_id,
            "engine": self.engine,
            "config_hash": self.config_hash,
            "inputs_snapshot": {
                "source": self.inputs_snapshot.source,
                "event_digest": self.inputs_snapshot.event_digest,
                "event_min": self.inputs_snapshot.event_min,
            },
            "features": self.features,
            "state_before": asdict(self.state_before),
            "score_delta": asdict(self.score_delta),
            "constraints_triggered": self.constraints_triggered,
            "chosen": [asdict(c) for c in self.chosen],
            "state_after": asdict(self.state_after),
            "parse_errors": self.parse_errors,
        }
        return json.dumps(d, separators=(",", ":"), ensure_ascii=True)


class DecisionLogger:
    """DecisionExplanation JSONL ロガー"""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Args:
            output_dir: JSONL出力先ディレクトリ
                       デフォルト: /opt/azazel-edge/logs/tactics_engine
        """
        if output_dir is None:
            self.output_dir = Path("/opt/azazel-edge/logs/tactics_engine")
        else:
            self.output_dir = Path(output_dir)

        self.output_file = self.output_dir / "decision_explanations.jsonl"
        self._ensure_directory()

    def _ensure_directory(self):
        """出力ディレクトリを作成（既存なら何もしない）"""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Failed to create output directory {self.output_dir}: {e}")

    def log_decision(self, record: DecisionRecord) -> bool:
        """
        DecisionRecord を JSONL に追記

        失敗時でもプロセス停止しない（ベストエフォート）

        Args:
            record: DecisionRecord インスタンス

        Returns:
            成功時 True、失敗時 False
        """
        try:
            json_line = record.to_json()
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")
            return True
        except Exception as e:
            logger.warning(f"Failed to write decision log to {self.output_file}: {e}")
            return False

    @staticmethod
    def create_record(
        engine_version: str,
        config_hash: str,
        inputs_source: str,
        event_digest: str,
        event_min: Optional[Dict[str, Any]],
        features: Dict[str, Any],
        state_before: StateSnapshot,
        score_delta: ScoreDelta,
        constraints_triggered: List[str],
        chosen: List[ChosenAction],
        state_after: StateSnapshot,
        parse_errors: Optional[Dict[str, int]] = None,
    ) -> DecisionRecord:
        """
        DecisionRecord をファクトリメソッドで作成

        Args:
            engine_version: Tactics Engine version
            config_hash: sha256:...
            inputs_source: "suricata" | "wifi" | "internal"
            event_digest: sha256:...
            event_min: 最小限のイベントデータ（dict）
            features: judge が抽出した特徴量（dict）
            state_before: 遷移前の状態
            score_delta: suspicion の変化
            constraints_triggered: 発動した制約リスト
            chosen: 選択された行動リスト
            state_after: 遷移後の状態
            parse_errors: パース失敗統計

        Returns:
            DecisionRecord インスタンス
        """
        if parse_errors is None:
            parse_errors = {}

        now = datetime.now(timezone.utc)
        ts = now.isoformat(timespec="milliseconds")

        return DecisionRecord(
            ts=ts,
            decision_id=str(uuid.uuid4()),
            engine={"name": "Tactics Engine", "version": engine_version},
            config_hash=config_hash,
            inputs_snapshot=InputSnapshot(
                source=inputs_source,
                event_digest=event_digest,
                event_min=event_min,
            ),
            features=features,
            state_before=state_before,
            score_delta=score_delta,
            constraints_triggered=constraints_triggered,
            chosen=chosen,
            state_after=state_after,
            parse_errors=parse_errors,
        )
