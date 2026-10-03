"""Dataset inspection and diagnostic reporting utility for network traffic data."""

import logging
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

logger = logging.getLogger("nids.dataset_inspector")


class DatasetInspector:
    """Comprehensive inspection utility reporting data types, distributions, and data-quality anomalies."""

    @classmethod
    def inspect(cls, df: pd.DataFrame, label_column: Optional[str] = None) -> Dict[str, Any]:
        """Perform deep diagnostic inspection on a network dataset DataFrame.

        Args:
            df: Input Pandas DataFrame.
            label_column: Optional explicit name of the target/label column.

        Returns:
            Dictionary containing structured inspection findings.
        """
        row_count = len(df)
        col_count = len(df.columns)
        memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)

        # 1. Duplicates
        duplicate_count = int(df.duplicated().sum())
        duplicate_pct = (duplicate_count / row_count * 100) if row_count > 0 else 0.0

        # 2. Missing & Infinite values
        missing_map: Dict[str, Dict[str, Any]] = {}
        infinite_map: Dict[str, int] = {}
        dtypes_map: Dict[str, str] = {}
        constant_cols: List[str] = []
        identifier_cols: List[str] = []
        problematic_cols: List[Dict[str, str]] = []

        for col in df.columns:
            series = df[col]
            dtypes_map[col] = str(series.dtype)

            # Check missing
            null_count = int(series.isna().sum())
            if null_count > 0:
                missing_map[col] = {
                    "count": null_count,
                    "percentage": round((null_count / row_count) * 100, 2),
                }

            # Check infinite values (numerical or string representations)
            inf_count = 0
            if pd.api.types.is_numeric_dtype(series):
                inf_count = int(np.isinf(series.dropna()).sum())
            elif pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series):
                inf_count = int(series.isin(["Infinity", "-Infinity", "Inf", "-Inf"]).sum())

            if inf_count > 0:
                infinite_map[col] = inf_count

            # Check unique count
            unique_count = int(series.nunique(dropna=False))

            # Highly constant columns
            if unique_count <= 1:
                constant_cols.append(col)
                problematic_cols.append({
                    "column": col,
                    "reason": "Constant column (0 or 1 unique values, zero variance)",
                })

            # Identifier-like columns
            col_lower = str(col).lower()
            is_id_name = any(k in col_lower for k in ["flow_id", "flow id", "timestamp", "session_id", "record_id"])
            if (unique_count == row_count and row_count > 10) or is_id_name:
                identifier_cols.append(col)

            # Problematic: High missing rate (>50%)
            if null_count > (0.5 * row_count) and row_count > 0:
                problematic_cols.append({
                    "column": col,
                    "reason": f"Severe missing rate ({round((null_count/row_count)*100, 1)}%)",
                })

            # Problematic: Contains infinite values
            if inf_count > 0:
                problematic_cols.append({
                    "column": col,
                    "reason": f"Contains {inf_count} infinite values (e.g. divide-by-zero)",
                })

        # 3. Label / Target detection and distribution
        detected_label_col = cls._detect_label_column(df, explicit=label_column)
        label_distribution: Dict[str, Dict[str, Any]] = {}

        if detected_label_col and detected_label_col in df.columns:
            val_counts = df[detected_label_col].value_counts(dropna=False)
            for lbl, cnt in val_counts.items():
                label_distribution[str(lbl)] = {
                    "count": int(cnt),
                    "percentage": round((cnt / row_count) * 100, 2) if row_count > 0 else 0.0,
                }

        # 4. Categorical columns summary
        categorical_cols = [
            c for c in df.columns
            if (pd.api.types.is_object_dtype(df[c]) or pd.api.types.is_string_dtype(df[c]))
            and c != detected_label_col
        ]
        categorical_summary = {
            c: {
                "unique_count": int(df[c].nunique()),
                "sample_values": [str(x) for x in df[c].dropna().unique()[:5]],
            }
            for c in categorical_cols
        }

        # 5. Numerical statistics
        num_df = df.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
        numerical_summary: Dict[str, Dict[str, float]] = {}
        if not num_df.empty:
            desc = num_df.describe().T
            for col_name, row in desc.iterrows():
                numerical_summary[str(col_name)] = {
                    "mean": round(float(row.get("mean", 0.0)), 3),
                    "std": round(float(row.get("std", 0.0)), 3),
                    "min": round(float(row.get("min", 0.0)), 3),
                    "median": round(float(row.get("50%", 0.0)), 3),
                    "max": round(float(row.get("max", 0.0)), 3),
                }

        report = {
            "row_count": row_count,
            "column_count": col_count,
            "memory_mb": round(memory_mb, 2),
            "duplicate_count": duplicate_count,
            "duplicate_percentage": round(duplicate_pct, 2),
            "columns": list(df.columns),
            "dtypes": dtypes_map,
            "missing_values": missing_map,
            "infinite_values": infinite_map,
            "detected_label_column": detected_label_col,
            "label_distribution": label_distribution,
            "categorical_columns": categorical_summary,
            "numerical_summary": numerical_summary,
            "constant_columns": constant_cols,
            "identifier_columns": identifier_cols,
            "problematic_columns": problematic_cols,
        }

        return report

    @staticmethod
    def _detect_label_column(df: pd.DataFrame, explicit: Optional[str] = None) -> Optional[str]:
        """Automatically identify the target/label column in network traffic datasets."""
        if explicit and explicit in df.columns:
            return explicit
        candidates = ["label", "Label", "LABEL", "class", "Class", "attack_cat", "threat_type"]
        for c in candidates:
            if c in df.columns:
                return c
        return None

    @classmethod
    def print_terminal_report(cls, report: Dict[str, Any], title: str = "DATASET INSPECTION REPORT") -> None:
        """Format and print an executive terminal report from inspection findings."""
        border = "=" * 80
        sub_border = "-" * 80

        print("\n" + border)
        print(f" {title.center(78)} ")
        print(border)

        print("\n[+] OVERVIEW METRICS:")
        print(f"  - Total Rows:             {report['row_count']:,}")
        print(f"  - Total Columns:          {report['column_count']}")
        print(f"  - Memory Footprint:       {report['memory_mb']} MB")
        print(f"  - Duplicate Records:      {report['duplicate_count']:,} ({report['duplicate_percentage']}%)")

        print("\n[+] TARGET / LABEL DISTRIBUTION:")
        if report.get("detected_label_column"):
            print(f"  - Detected Label Column:  '{report['detected_label_column']}'")
            for lbl, data in report.get("label_distribution", {}).items():
                print(f"    * {lbl:<28} : {data['count']:>6} flows ({data['percentage']:>5.1f}%)")
        else:
            print("  - No explicit label column identified.")

        print("\n[+] DATA QUALITY & HYGIENE FINDINGS:")
        missing_count = len(report.get("missing_values", {}))
        print(f"  - Columns with Missing Values:  {missing_count}")
        for col, data in report.get("missing_values", {}).items():
            print(f"    * {col:<32} : {data['count']:>5} nulls ({data['percentage']:>5.1f}%)")

        inf_count = len(report.get("infinite_values", {}))
        print(f"  - Columns with Infinite Values: {inf_count}")
        for col, count in report.get("infinite_values", {}).items():
            print(f"    * {col:<32} : {count:>5} infinite entries")

        print(f"  - Highly Constant Columns (0 or 1 unique values): {len(report.get('constant_columns', []))}")
        for col in report.get("constant_columns", []):
            print(f"    * {col}")

        print(f"  - Identifier-Like Columns (Potential Leakage):    {len(report.get('identifier_columns', []))}")
        for col in report.get("identifier_columns", []):
            print(f"    * {col}")

        if report.get("problematic_columns"):
            print("\n[!] ATTENTION: PROBLEMATIC COLUMNS DETECTED:")
            for item in report["problematic_columns"]:
                print(f"  * {item['column']:<30} -> {item['reason']}")
        else:
            print("\n[OK] No critical structural anomalies flagged.")

        print("\n" + border + "\n")


if __name__ == "__main__":
    from machine_learning.pipelines.dataset_loader import DatasetLoader

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    loader = DatasetLoader()
    raw_df, meta = loader.load_dataset()
    insp_report = DatasetInspector.inspect(raw_df)
    DatasetInspector.print_terminal_report(insp_report, title=f"INSPECTION: {meta['file_name']}")
