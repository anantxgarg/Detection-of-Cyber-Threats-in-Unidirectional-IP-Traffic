import math
import joblib
import redis


class DNSTunnelDetector:

    def __init__(self, model_path="dns_tunnel_model.pkl",
                 redis_client=None):

        # Load trained ML model
        self.model = joblib.load(model_path)

        # Redis is optional for standalone testing
        self.r = redis_client

        # Behavioral window
        self.window_seconds = 60

        # Supporting behavioral threshold
        # We are NOT using the old query-length >150 rule.
        self.rate_threshold = 50

        # Alert cooldown
        self.cooldown_seconds = 300


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
            log_request_response_ratio
        ]]


    # ==========================================
    # BEHAVIORAL ANALYSIS
    # ==========================================

    def behavioral_analysis(self, src_ip, base_domain, qtype):

        # If Redis is not connected, behavioral analysis
        # cannot be performed.
        if self.r is None:
            return 0.0, {}

        rate_key = (
            f"dns_tunnel_rate:{src_ip}:{base_domain}"
        )

        # Increment query count
        pipe = self.r.pipeline()
        pipe.incr(rate_key)
        pipe.expire(rate_key, self.window_seconds)
        results = pipe.execute()

        query_count = results[0]

        behavior_score = 0.0
        evidence = {
            "domain": base_domain,
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

        return min(1.0, behavior_score), evidence


    # ==========================================
    # MAIN ANALYSIS
    # ==========================================

    def analyze(self, data):

        query = data.get("query", "")

        if not query:
            return None

        # --------------------------------------
        # Determine base domain
        # --------------------------------------

        parts = query.split(".")

        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = query

        src_ip = data.get("src_ip", "unknown")
        qtype = data.get("qtype_name", "")


        # --------------------------------------
        # ML prediction
        # --------------------------------------

        features = self.extract_features(data)

        prediction = self.model.predict(features)[0]

        ml_score = float(
            self.model.predict_proba(features)[0][1]
        )


        # --------------------------------------
        # Behavioral analysis
        # --------------------------------------

        behavior_score, behavior_evidence = (
            self.behavioral_analysis(
                src_ip,
                base_domain,
                qtype
            )
        )


        # --------------------------------------
        # Combine scores
        # --------------------------------------

        # ML is the primary detector.
        # Behavioral evidence provides additional context.

        final_score = (
            0.75 * ml_score +
            0.25 * behavior_score
        )

        final_score = min(1.0, final_score)


        # --------------------------------------
        # Final classification
        # --------------------------------------

        if final_score >= 0.70:

            prediction_name = "DNS_Tunnelling"
            suspicion_level = "High"

        elif final_score >= 0.30:

            prediction_name = "Suspicious_DNS"
            suspicion_level = "Medium"

        else:

            prediction_name = "Benign"
            suspicion_level = "Low"


        # --------------------------------------
        # Evidence
        # --------------------------------------

        evidence = {

            "domain": base_domain,

            "query_example": query,

            "ml_score": ml_score,

            "behavior_score": behavior_score,

            "features": {
                "dns_query_length":
                    data.get("dns_query_length"),

                "dns_query_entropy":
                    data.get("dns_query_entropy"),

                "dns_subdomain_count":
                    data.get("dns_subdomain_count"),

                "dns_numerical_ratio":
                    data.get("dns_numerical_ratio"),

                "src2dst_bytes":
                    data.get("src2dst_bytes"),

                "dst2src_bytes":
                    data.get("dst2src_bytes")
            },

            "behavior": behavior_evidence
        }


        return {

            "detector_name":
                "DNS_Tunnel_Detector",

            "result": {

                "prediction":
                    prediction_name,

                "tunnel_score":
                    final_score,

                "suspicion_level":
                    suspicion_level
            },

            "evidence":
                evidence
        }


# ==========================================
# MODEL EVALUATION + DEMO
# ==========================================

if __name__ == "__main__":

    import pandas as pd
    from sklearn.metrics import (
        confusion_matrix,
        classification_report,
        accuracy_score
    )

    # --------------------------------------
    # Load dataset
    # --------------------------------------

    df = pd.read_csv("data/dataset_final.csv")

    detector = DNSTunnelDetector()

    print("\n" + "=" * 70)
    print("              DNS TUNNEL DETECTOR")
    print("=" * 70)


    # ======================================
    # MODEL EVALUATION
    # ======================================

    print("\n" + "=" * 70)
    print("                  MODEL EVALUATION")
    print("=" * 70)

    y_true = []
    y_pred = []

    # Use the same test set used during model evaluation
    from sklearn.model_selection import train_test_split

    feature_columns = [
        "dns_query_length",
        "dns_query_entropy",
        "dns_subdomain_count",
        "dns_numerical_ratio",
        "src2dst_bytes",
        "dst2src_bytes"
    ]

    X = df[feature_columns].copy()

    # Recreate engineered features
    X["request_response_ratio"] = (
        X["src2dst_bytes"] /
        (X["dst2src_bytes"] + 1)
    )

    X["log_src2dst_bytes"] = \
        X["src2dst_bytes"].apply(lambda x: math.log1p(x))

    X["log_dst2src_bytes"] = \
        X["dst2src_bytes"].apply(lambda x: math.log1p(x))

    X["log_request_response_ratio"] = \
        X["request_response_ratio"].apply(
            lambda x: math.log1p(x)
        )

    y = df["label"]

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    y_pred = detector.model.predict(X_test)

    # --------------------------------------
    # Accuracy
    # --------------------------------------

    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nAccuracy: {accuracy:.4f} ({accuracy:.2%})")


    # --------------------------------------
    # Confusion Matrix
    # --------------------------------------

    cm = confusion_matrix(y_test, y_pred)

    print("\nConfusion Matrix:")
    print("                 Predicted")
    print("              Benign  Tunnel")
    print(
        f"Actual Benign  {cm[0][0]:6d}  {cm[0][1]:6d}"
    )
    print(
        f"Actual Tunnel  {cm[1][0]:6d}  {cm[1][1]:6d}"
    )


    # --------------------------------------
    # Classification Report
    # --------------------------------------

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Benign",
                "DNS_Tunnelling"
            ],
            digits=4
        )
    )


    # ======================================
    # HUMAN-READABLE DEMO
    # ======================================

    print("\n" + "=" * 70)
    print("                 DETECTION DEMO")
    print("=" * 70)

    # --------------------------------------
    # Example DNS event
    # Change these values when you want
    # to test another example.
    # --------------------------------------

    demo_data = {

        "query": "abc123xyz.example.com",

        "dns_query_length": 22,

        "dns_query_entropy": 3.8,

        "dns_subdomain_count": 3,

        "dns_numerical_ratio": 0.14,

        "src2dst_bytes": 100,

        "dst2src_bytes": 180,

        "src_ip": "192.168.1.10",

        "qtype_name": "A"
    }

    result = detector.analyze(demo_data)


    # ======================================
    # HUMAN-READABLE RESULT
    # ======================================

    print("\nDNS Traffic:")
    print(f"  Domain            : {demo_data['query']}")
    print(f"  Query Type        : {demo_data['qtype_name']}")
    print(f"  Query Length      : {demo_data['dns_query_length']}")
    print(f"  Query Entropy     : {demo_data['dns_query_entropy']}")
    print(f"  Subdomain Count   : {demo_data['dns_subdomain_count']}")
    print(f"  Numerical Ratio   : {demo_data['dns_numerical_ratio']}")

    print("\nDetection Result:")
    print(
        f"  Prediction        : "
        f"{result['result']['prediction']}"
    )

    print(
        f"  Tunnel Score      : "
        f"{result['result']['tunnel_score']:.4f}"
    )

    print(
        f"  Suspicion Level   : "
        f"{result['result']['suspicion_level']}"
    )

    print("\nEvidence:")

    evidence = result["evidence"]

    print(
        f"  ML Score          : "
        f"{evidence['ml_score']:.4f}"
    )

    print(
        f"  Behavioral Score  : "
        f"{evidence['behavior_score']:.4f}"
    )

    print("\n" + "=" * 70)
    print("                    END")
    print("=" * 70)