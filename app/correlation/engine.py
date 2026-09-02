from __future__ import annotations

import networkx as nx

from app.correlation.features import compute_pair_features
from app.correlation.weighting import calculate_edge_weight
from app.schemas.alert import Alert


class CorrelationEngine:
    def __init__(
        self,
        temporal_window: float = 300.0,
        correlation_threshold: float = 0.5,
    ) -> None:
        self.temporal_window = temporal_window
        self.correlation_threshold = correlation_threshold

    def build_graph(self, alerts: list[Alert]) -> nx.Graph:
        graph = nx.Graph()

        for index, alert in enumerate(alerts):
            graph.add_node(index, alert=alert)

        for i in range(len(alerts)):
            for j in range(i + 1, len(alerts)):
                features = compute_pair_features(
                    alerts[i],
                    alerts[j],
                    temporal_window=self.temporal_window,
                )

                # Alerts outside the temporal window cannot
                # form a correlation edge, even if they share
                # the same source or destination.
                if features.time_delta > self.temporal_window:
                    continue

                weight = calculate_edge_weight(features)

                if weight >= self.correlation_threshold:
                    graph.add_edge(
                        i,
                        j,
                        weight=weight,
                        features=features,
                    )

        return graph

    def create_incidents(
        self,
        alerts: list[Alert],
    ) -> list[list[Alert]]:
        graph = self.build_graph(alerts)
        incidents: list[list[Alert]] = []

        for component in nx.connected_components(graph):
            incident = [
                graph.nodes[node]["alert"]
                for node in component
            ]
            incidents.append(incident)

        return incidents