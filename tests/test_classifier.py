import os

import numpy as np
import pytest

from ngfw.classifier import Classifier
from ngfw.config import load_config


pytestmark = pytest.mark.skipif(
    not os.path.exists("models/rf_model.pkl"),
    reason="Model artifact missing; run notebooks/01_train_model.ipynb first.",
)


def test_predict_returns_label_and_confidence():
    clf = Classifier(load_config())
    vec = np.zeros(len(clf.feature_names), dtype=float)
    label, conf = clf.predict(vec)
    assert label in clf.labels
    assert 0.0 <= conf <= 1.0


def test_wrong_shape_raises():
    clf = Classifier(load_config())
    with pytest.raises(ValueError):
        clf.predict(np.zeros(3))
