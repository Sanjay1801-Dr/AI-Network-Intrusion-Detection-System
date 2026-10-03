"""Dataset loading module supporting CIC-IDS2017, UNSW-NB15, and development samples."""

import glob
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import pandas as pd

logger = logging.getLogger("nids.dataset_loader")


class DatasetLoader:
    """Robust network traffic dataset loader with automatic fallback and schema resilience."""

    DEFAULT_RAW_DIR = Path("datasets/raw")
    DEFAULT_SAMPLE_PATH = Path("datasets/samples/sample_network_traffic.csv")

    def __init__(self, raw_dir: Optional[Union[str, Path]] = None) -> None:
        self.raw_dir = Path(raw_dir) if raw_dir else self.DEFAULT_RAW_DIR
        self.last_loaded_path: Optional[Path] = None
        self.is_sample_dataset: bool = False

    def find_available_raw_datasets(self) -> List[Path]:
        """Discover CSV files present in the raw datasets directory."""
        if not self.raw_dir.exists():
            return []
        csv_files = sorted(list(self.raw_dir.glob("*.csv")))
        return csv_files

    def load_dataset(
        self,
        file_path: Optional[Union[str, Path]] = None,
        max_rows: Optional[int] = None,
    ) -> Tuple[pd.DataFrame, Dict[str, Union[str, int, bool]]]:
        """Load a network traffic dataset into a Pandas DataFrame.

        If no file_path is specified, checks datasets/raw/ for available CSVs.
        If no raw CSV is found, gracefully falls back to the development sample.

        Args:
            file_path: Optional explicit path to a CSV dataset.
            max_rows: Optional limit on the number of rows to read.

        Returns:
            Tuple of (DataFrame, metadata dictionary).
        """
        target_path: Path

        if file_path:
            target_path = Path(file_path)
            if not target_path.exists():
                raise FileNotFoundError(f"Requested dataset file not found at: {target_path}")
            self.is_sample_dataset = "samples" in str(target_path).lower()
        else:
            raw_files = self.find_available_raw_datasets()
            if raw_files:
                target_path = raw_files[0]
                self.is_sample_dataset = False
                logger.info("Found raw dataset in %s: %s", self.raw_dir, target_path.name)
            else:
                target_path = self.DEFAULT_SAMPLE_PATH
                self.is_sample_dataset = True
                logger.info(
                    "No raw CSV found in '%s'. Falling back to development sample: '%s'",
                    self.raw_dir,
                    target_path,
                )

        if not target_path.exists():
            raise FileNotFoundError(
                f"Neither raw dataset nor development sample found at '{target_path}'. "
                f"Please ensure '{self.DEFAULT_SAMPLE_PATH}' exists."
            )

        self.last_loaded_path = target_path

        # Read CSV with encoding fallback and comment parsing
        df = self._read_csv_resilient(target_path, nrows=max_rows)

        # Strip accidental whitespace from column headers immediately
        df.columns = df.columns.astype(str).str.strip()

        metadata = {
            "file_name": target_path.name,
            "file_path": str(target_path.resolve()),
            "file_size_bytes": os.path.getsize(target_path),
            "is_sample_dataset": self.is_sample_dataset,
            "raw_row_count": len(df),
            "raw_column_count": len(df.columns),
        }

        logger.info(
            "Loaded dataset '%s' with %d rows and %d columns (Sample: %s)",
            target_path.name,
            len(df),
            len(df.columns),
            self.is_sample_dataset,
        )

        return df, metadata

    @staticmethod
    def _read_csv_resilient(path: Path, nrows: Optional[int] = None) -> pd.DataFrame:
        """Read CSV attempting UTF-8 first, falling back to Latin-1, skipping comment lines."""
        encodings = ["utf-8", "latin-1", "cp1252"]
        last_error = None

        for enc in encodings:
            try:
                # Support comment headers starting with '#'
                df = pd.read_csv(
                    path,
                    comment="#",
                    skipinitialspace=True,
                    nrows=nrows,
                    encoding=enc,
                    low_memory=False,
                )
                return df
            except UnicodeDecodeError as exc:
                last_error = exc
                continue
            except Exception as exc:
                last_error = exc
                break

        raise RuntimeError(f"Failed to read CSV at '{path}' with supported encodings: {last_error}")
