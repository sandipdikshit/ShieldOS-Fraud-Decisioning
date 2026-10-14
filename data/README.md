# Data provenance

The checked-in extract is derived from [OpenML dataset 1597, `creditcard`](https://www.openml.org/d/1597), version 1. The source contains 284,807 anonymized card transactions made by European cardholders over two days in September 2013, including 492 transactions labelled as fraud. `V1`–`V28` are PCA-transformed features; `Time`, `Amount`, and `Class` retain their published meanings.

## Reproducible extract

`creditcard_openml_1597_extract.csv.gz` contains every labelled fraud row and a deterministic sample of legitimate rows, sorted by source time. This preserves rare positive examples for the demonstration but changes class prevalence. Use `sampling_weight` for prevalence or volume estimates; do not treat unweighted extract metrics as population metrics.

| Artifact | SHA-256 |
|---|---|
| OpenML ARFF source | `fdaf12730dc1fc426f318b71349f24f5c5fd00aa1152940be7e7509ae3d89d2a` |
| Checked-in CSV extract | `cf7398ad15c1a99e5cb48f3c1affd85def53b128a34ce2ee1af5805904f2ed0f` |
| Extract manifest | `98694d3864e4b637ccbebd45d1c441caa488f5a1c1d0cac8c4336cd6a5ff5baa` |

Verify or rebuild it from the repository root:

```bash
shasum -a 256 data/creditcard_openml_1597_extract.csv.gz \
  data/creditcard_openml_1597_manifest.json
python scripts/build_data_extract.py
```

The complete extraction recipe, source URL, row counts, sampling seed, and hashes are recorded in `creditcard_openml_1597_manifest.json` and `scripts/build_data_extract.py`.

## Evidence boundary

The observed OpenML columns support demonstrations of imbalanced fraud classification, chronological evaluation, calibration, threshold trade-offs, value-weighted capture, and drift. They do **not** include customer identity, device ID, IP address, IMSI/IMEI, carrier events, authentication history, payee novelty, or investigator outcomes.

ShieldOS adds device trust, SIM-change state, IP reputation, impossible travel, velocity, idempotency, timeout, and routing inputs only as explicitly labelled scenario fixtures. These fields illustrate the production contract and orchestration path; they are not observations from OpenML or a bank. The multi-agent investigation is likewise a controlled workflow simulation, not evidence of autonomous production enforcement.

The repository's MIT license covers the project code. It does not relicense the third-party dataset; consult the OpenML dataset page and original ULB source for dataset terms and attribution.
