import math


def extract_dns_features(row):
    """
    Extract features used by the DNS Tunnel Detector.
    """

    # DNS behaviour
    query_length = float(row.get("dns_query_length", 0))
    query_entropy = float(row.get("dns_query_entropy", 0))
    subdomain_count = float(row.get("dns_subdomain_count", 0))
    numerical_ratio = float(row.get("dns_numerical_ratio", 0))

    # Directional traffic behaviour
    src2dst_bytes = float(row.get("src2dst_bytes", 0))
    dst2src_bytes = float(row.get("dst2src_bytes", 0))

    # Request / response relationship
    request_response_ratio = (
        src2dst_bytes / (dst2src_bytes + 1)
    )

    # Log transformations for highly skewed traffic features
    log_src2dst_bytes = math.log1p(src2dst_bytes)
    log_dst2src_bytes = math.log1p(dst2src_bytes)
    log_request_response_ratio = math.log1p(request_response_ratio)

    return {
        "dns_query_length": query_length,
        "dns_query_entropy": query_entropy,
        "dns_subdomain_count": subdomain_count,
        "dns_numerical_ratio": numerical_ratio,

        "src2dst_bytes": src2dst_bytes,
        "dst2src_bytes": dst2src_bytes,
        "request_response_ratio": request_response_ratio,

        "log_src2dst_bytes": log_src2dst_bytes,
        "log_dst2src_bytes": log_dst2src_bytes,
        "log_request_response_ratio": log_request_response_ratio,
    }