import math
import joblib


class DNSTunnelDetector:
    def __init__(self, model_path="dns_tunnel_model.pkl"):
        # Load trained XGBoost model
        self.model = joblib.load(model_path)

    def extract_features(self, data):
        """
        Extract the same features used during model training.
        """

        dns_query_length = float(data.get("dns_query_length", 0))
        dns_query_entropy = float(data.get("dns_query_entropy", 0))
        dns_subdomain_count = float(data.get("dns_subdomain_count", 0))
        dns_numerical_ratio = float(data.get("dns_numerical_ratio", 0))

        src2dst_bytes = float(data.get("src2dst_bytes", 0))
        dst2src_bytes = float(data.get("dst2src_bytes", 0))

        request_response_ratio = (
            src2dst_bytes / (dst2src_bytes + 1)
        )

        log_src2dst_bytes = math.log1p(src2dst_bytes)
        log_dst2src_bytes = math.log1p(dst2src_bytes)
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

    def analyze(self, data):
        """
        Analyze one DNS flow.
        """

        features = self.extract_features(data)

        # Prediction
        prediction = self.model.predict(features)[0]

        # Probability of DNS tunnelling
        tunnel_score = self.model.predict_proba(features)[0][1]

        if prediction == 1:
            prediction_name = "DNS_Tunnelling"
        else:
            prediction_name = "Benign"

        # Suspicion level
        if tunnel_score < 0.30:
            suspicion_level = "Low"
        elif tunnel_score < 0.70:
            suspicion_level = "Medium"
        else:
            suspicion_level = "High"

        return {
            "detector_name": "DNS_Tunnel_Detector",

            "result": {
                "prediction": prediction_name,
                "tunnel_score": float(tunnel_score),
                "suspicion_level": suspicion_level
            },

            "evidence": {
                "features": {
                    "dns_query_length": data.get("dns_query_length"),
                    "dns_query_entropy": data.get("dns_query_entropy"),
                    "dns_subdomain_count": data.get("dns_subdomain_count"),
                    "dns_numerical_ratio": data.get("dns_numerical_ratio"),
                    "src2dst_bytes": data.get("src2dst_bytes"),
                    "dst2src_bytes": data.get("dst2src_bytes")
                }
            }
        }


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    detector = DNSTunnelDetector()

    # Example benign DNS flow
    benign = {
        "dns_query_length": 35,
        "dns_query_entropy": 3.8,
        "dns_subdomain_count": 5,
        "dns_numerical_ratio": 0.04,
        "src2dst_bytes": 98,
        "dst2src_bytes": 170
    }

    # Example suspicious DNS flow
    suspicious = {
        "dns_query_length": 25,
        "dns_query_entropy": 3.3,
        "dns_subdomain_count": 3,
        "dns_numerical_ratio": 0.13,
        "src2dst_bytes": 50000,
        "dst2src_bytes": 200
    }

    print("\n===== BENIGN TEST =====")
    print(detector.analyze(benign))

    print("\n===== SUSPICIOUS TEST =====")
    print(detector.analyze(suspicious))