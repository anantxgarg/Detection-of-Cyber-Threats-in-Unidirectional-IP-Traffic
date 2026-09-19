from pathlib import Path
from collections import Counter
import math

import pandas as pd
import shap
from scipy.sparse import hstack

from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
from src.detection.model_loader import load_model


class DGADetector:
    def __init__(self):
        # Load DGA detection models from canonical models directory
        self.model = load_model("combined_dga_model.pkl", "dga")
        self.vectorizer = load_model("ngram_vectorizer.pkl", "dga")

        self.feature_columns = [
            "domain_length",
            "num_labels",
            "longest_label_length",
            "entropy",
            "digit_ratio",
            "vowel_ratio",
            "hyphen_ratio",
            "unique_character_ratio",
            "max_consecutive_consonants",
        ]

        # SHAP explainer for the combined sparse feature space.
        # SHAP is calculated only for actual DGA alerts.
        background_domain = "example"
        background_ngram = self.vectorizer.transform([background_domain])

        background_features = self._extract_features(background_domain)
        background_df = pd.DataFrame(
            [background_features],
            columns=self.feature_columns,
        )

        background_combined = hstack(
            [
                background_ngram,
                background_df.values,
            ]
        ).tocsr()

        self.shap_explainer = shap.LinearExplainer(
            self.model,
            background_combined,
        )

        self.ngram_feature_names = list(
            self.vectorizer.get_feature_names_out()
        )

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0

        entropy = 0.0

        for count in Counter(data).values():
            probability = count / len(data)
            entropy -= probability * math.log(probability, 2)

        return entropy

    def _extract_features(self, domain: str) -> dict:
        domain = domain.lower().strip().rstrip(".")

        labels = domain.split(".")

        domain_length = len(domain)
        num_labels = len(labels)

        longest_label_length = max(
            (len(label) for label in labels),
            default=0,
        )

        entropy = self._shannon_entropy(domain)

        digit_ratio = (
            sum(character.isdigit() for character in domain)
            / domain_length
            if domain_length
            else 0.0
        )

        vowel_ratio = (
            sum(character in "aeiou" for character in domain)
            / domain_length
            if domain_length
            else 0.0
        )

        hyphen_ratio = (
            domain.count("-") / domain_length
            if domain_length
            else 0.0
        )

        unique_character_ratio = (
            len(set(domain)) / domain_length
            if domain_length
            else 0.0
        )

        max_consecutive_consonants = 0
        current_consonants = 0

        for character in domain:
            if character.isalpha() and character not in "aeiou":
                current_consonants += 1

                max_consecutive_consonants = max(
                    max_consecutive_consonants,
                    current_consonants,
                )
            else:
                current_consonants = 0

        return {
            "domain_length": domain_length,
            "num_labels": num_labels,
            "longest_label_length": longest_label_length,
            "entropy": entropy,
            "digit_ratio": digit_ratio,
            "vowel_ratio": vowel_ratio,
            "hyphen_ratio": hyphen_ratio,
            "unique_character_ratio": unique_character_ratio,
            "max_consecutive_consonants": max_consecutive_consonants,
        }

    def _get_shap_evidence(self, shap_values) -> list[dict]:
        values = shap_values.values[0]

        # Get indices of the five largest absolute contributions.
        top_indices = sorted(
            range(len(values)),
            key=lambda index: abs(values[index]),
            reverse=True,
        )[:5]

        explanations = []

        total_ngram_features = len(self.ngram_feature_names)

        for index in top_indices:
            contribution = float(values[index])

            if index < total_ngram_features:
                feature_name = self.ngram_feature_names[index]
                feature_type = "character_ngram"
            else:
                handcrafted_index = index - total_ngram_features

                if handcrafted_index >= len(self.feature_columns):
                    continue

                feature_name = self.feature_columns[handcrafted_index]
                feature_type = "handcrafted"

            explanations.append(
                {
                    "feature": feature_name,
                    "type": feature_type,
                    "contribution": round(contribution, 6),
                    "direction": (
                        "toward_DGA"
                        if contribution > 0
                        else "away_from_DGA"
                    ),
                }
            )

        return explanations

    def analyze(
        self,
        event: NormalizedEvent,
    ) -> DetectionResult | None:

        if event.log_type != "dns":
            return None

        query = event.data.get("query")

        if not query:
            return None

        query = str(query).lower().strip().rstrip(".")

        parts = query.split(".")

        if len(parts) < 2:
            return None

        # The friend's model uses the domain body for prediction.
        domain_body = parts[-2]

        handcrafted_features = self._extract_features(
            domain_body
        )

        # Character n-gram features.
        ngram_features = self.vectorizer.transform(
            [domain_body]
        )

        handcrafted_df = pd.DataFrame(
            [handcrafted_features],
            columns=self.feature_columns,
        )

        # Exact feature structure used by the trained model.
        combined_features = hstack(
            [
                ngram_features,
                handcrafted_df.values,
            ]
        ).tocsr()

        prediction = int(
            self.model.predict(combined_features)[0]
        )

        probabilities = self.model.predict_proba(
            combined_features
        )[0]

        # Class 1 = DGA.
        dga_score = float(probabilities[1])

        # Only generate SHAP for an actual DGA alert.
        if prediction != 1:
            return None

        shap_values = self.shap_explainer(
            combined_features
        )

        shap_evidence = self._get_shap_evidence(
            shap_values
        )

        return DetectionResult(
            timestamp=event.ts,
            flow_id=event.data.get("uid"),
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            threat_class=ThreatClass.DGA,
            confidence=dga_score,
            evidence={
                "query": query,
                "domain": domain_body,
                "dga_score": round(dga_score, 4),
                "prediction": prediction,
                "model_used": "combined_dga_model",
                "features": {
                    key: round(value, 4)
                    if isinstance(value, float)
                    else value
                    for key, value in handcrafted_features.items()
                },
                "shap": shap_evidence,
            },
            protocol=event.data.get("proto"),
        )