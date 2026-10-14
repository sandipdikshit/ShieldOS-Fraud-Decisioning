#!/usr/bin/env python3
"""Build the checked-in ShieldOS extract from OpenML dataset 1597."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path

import pandas as pd


OPENML_DATASET_ID = 1597
OPENML_VERSION = 1
OPENML_URL = "https://www.openml.org/data/v1/download/1673544/creditcard.arff"
RANDOM_STATE = 42
EXTRACT_ROWS = 3_000
COLUMNS = ["Time", *[f"V{i}" for i in range(1, 29)], "Amount", "Class"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def data_line(path: Path) -> int:
    with path.open("r", encoding="utf-8") as stream:
        for index, line in enumerate(stream):
            if line.strip().lower() == "@data":
                return index + 1
    raise ValueError(f"No @data marker found in {path}")


def load_arff(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(
        path,
        skiprows=data_line(path),
        names=COLUMNS,
        quotechar="'",
        dtype={"Class": "int8"},
    )
    frame.insert(0, "_source_row_number", range(len(frame)))
    return frame


def build_extract(frame: pd.DataFrame) -> pd.DataFrame:
    fraud = frame.loc[frame["Class"] == 1]
    legitimate = frame.loc[frame["Class"] == 0]
    legitimate_sample_size = EXTRACT_ROWS - len(fraud)
    if legitimate_sample_size <= 0:
        raise ValueError("Extract size must be larger than the fraud population")

    legitimate_sample = legitimate.sample(
        n=legitimate_sample_size,
        random_state=RANDOM_STATE,
        replace=False,
    )
    extract = pd.concat([fraud, legitimate_sample], ignore_index=True)
    extract["sampling_weight"] = 1.0
    extract.loc[extract["Class"] == 0, "sampling_weight"] = (
        len(legitimate) / legitimate_sample_size
    )
    return extract.sort_values(
        ["Time", "_source_row_number"], kind="stable"
    ).reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(tempfile.gettempdir()) / "openml-creditcard-1597.arff",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("data"))
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.source.exists():
        print(f"Downloading OpenML dataset {OPENML_DATASET_ID}...")
        urllib.request.urlretrieve(OPENML_URL, args.source)

    frame = load_arff(args.source)
    extract = build_extract(frame)
    extract_path = args.output_dir / "creditcard_openml_1597_extract.csv.gz"
    extract.to_csv(
        extract_path,
        index=False,
        compression={"method": "gzip", "compresslevel": 9, "mtime": 0},
        float_format="%.12g",
    )

    manifest = {
        "openml_dataset_id": OPENML_DATASET_ID,
        "openml_version": OPENML_VERSION,
        "source_url": OPENML_URL,
        "source_sha256": sha256(args.source),
        "source_rows": int(len(frame)),
        "source_fraud_rows": int(frame["Class"].sum()),
        "source_fraud_prevalence": float(frame["Class"].mean()),
        "extract_rows": int(len(extract)),
        "extract_fraud_rows": int(extract["Class"].sum()),
        "extract_strategy": (
            "all labelled fraud rows plus a deterministic sample of legitimate rows"
        ),
        "random_state": RANDOM_STATE,
        "derived_columns": ["_source_row_number", "sampling_weight"],
        "extract_sha256": sha256(extract_path),
        "metric_policy": (
            "Use sampling_weight for prevalence and volume estimates; treat the "
            "extract as a reproducible engineering demonstration, not a benchmark."
        ),
    }
    manifest_path = args.output_dir / "creditcard_openml_1597_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
