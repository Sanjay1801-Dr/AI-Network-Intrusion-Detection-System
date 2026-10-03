"""Feature engineering module for extracting network flow behavioral indicators."""

import logging
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

logger = logging.getLogger("nids.feature_engineering")


class NetworkFeatureEngineer(BaseEstimator, TransformerMixin):
    """Dynamically extracts high-signal cybersecurity flow metrics from raw flow telemetry.

    Features are only computed if the requisite prerequisite columns exist in the DataFrame.
    """

    def __init__(self, add_port_type: bool = True, add_ratios: bool = True) -> None:
        self.add_port_type = add_port_type
        self.add_ratios = add_ratios
        self.engineered_feature_names_: List[str] = []

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "NetworkFeatureEngineer":
        """Fit estimator — captures input structure without data snooping."""
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Engineer new features dynamically based on available columns in X.

        Args:
            X: Input DataFrame of network traffic flows.

        Returns:
            DataFrame enriched with engineered features.
        """
        df = X.copy()
        new_cols: List[str] = []

        # 1. Total Packet & Byte volume if split by direction
        has_fwd_pkts = self._find_col(df, ["total_fwd_packets", "total_fwd_packet", "fwd_packets"])
        has_bwd_pkts = self._find_col(df, ["total_backward_packets", "total_bwd_packets", "bwd_packets"])
        has_fwd_bytes = self._find_col(df, ["total_length_of_fwd_packets", "total_fwd_bytes", "fwd_bytes"])
        has_bwd_bytes = self._find_col(df, ["total_length_of_bwd_packets", "total_bwd_bytes", "bwd_bytes"])
        has_duration = self._find_col(df, ["flow_duration", "duration", "duration_seconds"])

        # Total packets
        if has_fwd_pkts and has_bwd_pkts and "total_packets" not in df.columns:
            df["total_packets"] = df[has_fwd_pkts].fillna(0) + df[has_bwd_pkts].fillna(0)
            new_cols.append("total_packets")

        # Total bytes
        if has_fwd_bytes and has_bwd_bytes and "total_bytes" not in df.columns:
            df["total_bytes"] = df[has_fwd_bytes].fillna(0) + df[has_bwd_bytes].fillna(0)
            new_cols.append("total_bytes")

        # 2. Rate Metrics: Packets/s and Bytes/s
        duration_col = self._find_col(df, ["flow_duration", "duration", "duration_seconds"])
        total_pkts_col = self._find_col(df, ["total_packets", "tot_pkts"])
        total_bytes_col = self._find_col(df, ["total_bytes", "tot_bytes"])

        if duration_col and total_pkts_col:
            # Prevent divide by zero using 1 microsecond epsilon
            epsilon = 1e-6
            duration_sec = df[duration_col].astype(float).clip(lower=epsilon)
            # If duration is in microseconds (CIC-IDS2017 standard), convert to seconds
            if duration_sec.median() > 1000:
                duration_sec = duration_sec / 1e6

            if "calc_flow_packets_per_s" not in df.columns and "flow_packets_s" not in df.columns:
                df["calc_flow_packets_per_s"] = df[total_pkts_col] / duration_sec
                new_cols.append("calc_flow_packets_per_s")

            if total_bytes_col and "calc_flow_bytes_per_s" not in df.columns and "flow_bytes_s" not in df.columns:
                df["calc_flow_bytes_per_s"] = df[total_bytes_col] / duration_sec
                new_cols.append("calc_flow_bytes_per_s")

        # 3. Ratio Metrics (Asymmetry & Port Scanning Signatures)
        if self.add_ratios:
            # Forward vs Backward Packet Ratio
            if has_fwd_pkts and has_bwd_pkts and "fwd_bwd_packet_ratio" not in df.columns:
                df["fwd_bwd_packet_ratio"] = df[has_fwd_pkts] / (df[has_bwd_pkts] + 1.0)
                new_cols.append("fwd_bwd_packet_ratio")

            # Forward vs Backward Byte Ratio
            if has_fwd_bytes and has_bwd_bytes and "fwd_bwd_byte_ratio" not in df.columns:
                df["fwd_bwd_byte_ratio"] = df[has_fwd_bytes] / (df[has_bwd_bytes] + 1.0)
                new_cols.append("fwd_bwd_byte_ratio")

            # SYN Flag Ratio (Extremely high in SYN floods and port probes)
            syn_col = self._find_col(df, ["syn_flag_count", "syn_count", "syn_flags", "fwd_psh_flags"])
            if syn_col and total_pkts_col and "syn_ratio" not in df.columns:
                df["syn_ratio"] = df[syn_col].fillna(0) / (df[total_pkts_col].fillna(0) + 1.0)
                new_cols.append("syn_ratio")

            # RST Flag Ratio (Elevated when targets reject connections during scanning)
            rst_col = self._find_col(df, ["rst_flag_count", "rst_count", "rst_flags"])
            if rst_col and total_pkts_col and "rst_ratio" not in df.columns:
                df["rst_ratio"] = df[rst_col].fillna(0) / (df[total_pkts_col].fillna(0) + 1.0)
                new_cols.append("rst_ratio")

        # 4. Average Packet Size
        if total_bytes_col and total_pkts_col and "calc_avg_packet_size" not in df.columns and "average_packet_size" not in df.columns:
            df["calc_avg_packet_size"] = df[total_bytes_col] / (df[total_pkts_col] + 1.0)
            new_cols.append("calc_avg_packet_size")

        # 5. Destination Port Class Category
        dst_port_col = self._find_col(df, ["destination_port", "dst_port", "dport"])
        if dst_port_col and self.add_port_type and "port_category" not in df.columns:
            df["port_category"] = df[dst_port_col].apply(self._classify_port)
            new_cols.append("port_category")

        self.engineered_feature_names_ = new_cols
        logger.info("Engineered %d new behavioral features: %s", len(new_cols), new_cols)
        return df

    @staticmethod
    def _find_col(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
        """Find matching column case-insensitively with or without underscores."""
        df_cols_clean = {c.lower().replace(" ", "_"): c for c in df.columns}
        for cand in candidates:
            cleaned = cand.lower().replace(" ", "_")
            if cleaned in df_cols_clean:
                return df_cols_clean[cleaned]
        return None

    @staticmethod
    def _classify_port(port_val: Any) -> str:
        """Classify port into standard IANA tiers: Well-known, Registered, or Dynamic."""
        try:
            port = int(port_val)
            if 0 <= port <= 1023:
                return "well_known"
            elif 1024 <= port <= 49151:
                return "registered"
            elif 49152 <= port <= 65535:
                return "dynamic"
            return "unknown"
        except (ValueError, TypeError):
            return "unknown"
