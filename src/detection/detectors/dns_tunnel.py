import math
import redis
import shap
from pathlib import Path

from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
from src.detection.model_loader import load_model


class DNSTunnelDetector:

    def __init__(self, redis_client=None):
        # Load DNS tunnel detection model from canonical models directory
        self.model = load_model("dns_tunnel_model.pkl", "dns_tunnel")

        # Redis is used for behavioral analysis
        self.r = redis_client

        # Behavioral window
        self.window_seconds = 60

        # Supporting behavioral threshold
        self.rate_threshold = 50

        # Alert cooldown
        self.cooldown_seconds = 300

        # SHAP explainer for the XGBoost model
        self.shap_explainer = shap.TreeExplainer(self.model)

        # Exact feature order used by the trained model
        self.feature_columns = [
            "dns_query_length",
            "dns_query_entropy",
            "dns_subdomain_count",
            "dns_numerical_ratio",
            "src2dst_bytes",
            "dst2src_bytes",
            "request_response_ratio",
            "log_src2dst_bytes",
            "log_dst2src_bytes",
            "log_request_response_ratio",
        ]

    # ==========================================
    # FEATURE EXTRACTION
    # ==========================================

    def extract_features(self, data):

        dns_query_length = float(
            data.get("dns_query_length", 0)
        )

        dns_query_entropy = float(
            data.get("dns_query_entropy", 0)
        )

        dns_subdomain_count = float(
            data.get("dns_subdomain_count", 0)
        )

        dns_numerical_ratio = float(
            data.get("dns_numerical_ratio", 0)
        )

        src2dst_bytes = float(
            data.get("src2dst_bytes", 0)
        )

        dst2src_bytes = float(
            data.get("dst2src_bytes", 0)
        )

        request_response_ratio = (
            src2dst_bytes / (dst2src_bytes + 1)
        )

        log_src2dst_bytes = math.log1p(
            src2dst_bytes
        )

        log_dst2src_bytes = math.log1p(
            dst2src_bytes
        )

        log_request_response_ratio = math.log1p(
            request_response_ratio
        )

        return [[
            dns_query_length,
            dns_query_entropy,
            dns_subdomain_count,
            dns_numerical_ratio,
            src2dst_bytes,
            dst2src_bytes,
            request_response_ratio,
            log_src2dst_bytes,
            log_dst2src_bytes,
            log_request_response_ratio,
        ]]

    # ==========================================
    # BEHAVIORAL ANALYSIS
    # ==========================================

    def behavioral_analysis(
        self,
        src_ip,
        base_domain,
        qtype,
    ):

        if self.r is None:
            return 0.0, {}

        rate_key = (
            f"dns_tunnel_rate:"
            f"{src_ip}:"
            f"{base_domain}"
        )

        pipe = self.r.pipeline()

        pipe.incr(rate_key)
        pipe.expire(
            rate_key,
            self.window_seconds
        )

        results = pipe.execute()

        query_count = results[0]

        behavior_score = 0.0

        evidence = {
            "query_count_60s": query_count
        }

        # High query rate
        if query_count > self.rate_threshold:

            behavior_score += 0.6

            evidence["high_query_rate"] = True

        # TXT / NULL are supporting indicators
        if qtype in ["TXT", "NULL"]:

            behavior_score += 0.4

            evidence["suspicious_qtype"] = qtype

        return (
            min(1.0, behavior_score),
            evidence,
        )

    # ==========================================
    # SHAP EXPLANATION
    # ==========================================

    def _get_shap_evidence(self, feature_values):

        try:

            shap_values = (
                self.shap_explainer.shap_values(
                    feature_values
                )
            )

            # Handle different SHAP return formats
            if hasattr(shap_values, "values"):
                shap_values = shap_values.values

            if isinstance(shap_values, list):
                shap_values = shap_values[0]

            # Convert to a flat list
            shap_values = shap_values[0]

            contributions = []

            for feature, contribution in zip(
                self.feature_columns,
                shap_values,
            ):

                contribution = float(
                    contribution
                )

                contributions.append({
                    "feature": feature,
                    "contribution": round(
                        contribution,
                        6,
                    ),
                    "direction": (
                        "toward_DNS_Tunnelling"
                        if contribution > 0
                        else "away_from_DNS_Tunnelling"
                    ),
                })

            # Top 5 absolute SHAP contributions
            contributions.sort(
                key=lambda x: abs(
                    x["contribution"]
                ),
                reverse=True,
            )

            return contributions[:5]

        except Exception as e:

            return {
                "error": str(e)
            }

    # ==========================================
    # MAIN ANALYSIS
    # ==========================================

    def analyze(self, event: NormalizedEvent):

        if event.log_type != "dns":
            return None

        data = event.data

        query = data.get("query", "")

        if not query:
            return None

        # --------------------------------------
        # Determine base domain
        # --------------------------------------

        parts = query.split(".")

        if len(parts) >= 2:
            base_domain = ".".join(
                parts[-2:]
            )
        else:
            base_domain = query

        src_ip = event.src_ip

        qtype = data.get(
            "qtype_name",
            "",
        )

        # --------------------------------------
        # ML prediction
        # --------------------------------------

        feature_values = (
            self.extract_features(data)
        )

        prediction = self.model.predict(
            feature_values
        )[0]

        ml_score = float(
            self.model.predict_proba(
                feature_values
            )[0][1]
        )

        # --------------------------------------
        # Behavioral analysis
        # --------------------------------------

        (
            behavior_score,
            behavior_evidence,
        ) = self.behavioral_analysis(
            src_ip,
            base_domain,
            qtype,
        )

        # --------------------------------------
        # Combine scores
        # --------------------------------------

        # ML is the primary detector.
        # Behavioral evidence provides
        # additional context.

        final_score = (
            0.75 * ml_score
            + 0.25 * behavior_score
        )

        final_score = min(
            1.0,
            final_score,
        )

        # --------------------------------------
        # Alert threshold
        # --------------------------------------

        # IMPORTANT:
        # SHAP is calculated ONLY when the
        # final score crosses the alert threshold.

        if final_score < 0.70:
            return None

        # --------------------------------------
        # SHAP explanation
        # --------------------------------------

        shap_evidence = (
            self._get_shap_evidence(
                feature_values
            )
        )

        # --------------------------------------
        # Redis cooldown
        # --------------------------------------

        alert_key = (
            f"alert_cooldown:"
            f"dnstunnel:"
            f"{src_ip}:"
            f"{base_domain}"
        )

        if self.r is not None:

            if self.r.get(alert_key):
                return None

            self.r.setex(
                alert_key,
                self.cooldown_seconds,
                "1",
            )

        # --------------------------------------
        # Evidence
        # --------------------------------------

        evidence = {

            "domain": base_domain,

            "query_example": query,

            "ml_prediction": int(
                prediction
            ),

            "ml_score": round(
                ml_score,
                4,
            ),

            "behavior_score": round(
                behavior_score,
                4,
            ),

            "final_score": round(
                final_score,
                4,
            ),

            "model_used":
                "dns_tunnel_model",

            "features": {
                feature: value
                for feature, value in zip(
                    self.feature_columns,
                    feature_values[0],
                )
            },

            "behavior":
                behavior_evidence,

            "shap":
                shap_evidence,
        }

        # --------------------------------------
        # Detection Result
        # --------------------------------------

        return DetectionResult(

            timestamp=event.ts,

            flow_id=event.data.get(
                "uid"
            ),

            src_ip=event.src_ip,

            dst_ip=event.dst_ip,

            protocol=(
                event.data.get("proto")
                if isinstance(
                    event.data.get("proto"),
                    str,
                )
                else None
            ),

            threat_class=
                ThreatClass.DNS_TUNNELLING,

            confidence=final_score,

            evidence=evidence,
        )