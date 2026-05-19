import json
from pathlib import Path

import joblib
import numpy as np

from ngfw.config import Config


class Classifier:
    def __init__(self, cfg: Config) -> None:
        self.model = joblib.load(cfg.model_path)
        self.scaler = joblib.load(cfg.scaler_path)
        # labels MUST come from training metrics to avoid drift
        metrics_path = cfg.model_path.parent / "metrics.json"
        with open(metrics_path) as f:
            meta = json.load(f)
        self.labels: list[str] = meta["labels"]
        self.feature_names: list[str] = meta["features"]
        if tuple(self.labels) != cfg.labels:
            raise RuntimeError(
                f"Label mismatch: model has {self.labels}, config expects {cfg.labels}"
            )

    def predict(self, vec: np.ndarray) -> tuple[str, float]:
        if vec.shape != (len(self.feature_names),):
            raise ValueError(f"Expected shape ({len(self.feature_names)},), got {vec.shape}")
        x = self.scaler.transform(vec.reshape(1, -1))
        proba = self.model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        return self.labels[idx], float(proba[idx])
