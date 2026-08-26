<!-- Last updated 2026-08-27. -->
# DATA SOURCES

Every raw input to this project, with license and retrieval date, so the write-up can
cite it correctly. Nothing here is committed to the repository — `data/raw/` is
gitignored and `make data` refetches it.

**All retrievals: 2026-08-26.**

---

## 1. VERIS Community Database (VCDB)

| | |
|---|---|
| **Role in project** | Data spine — supplies real incident classifications (SCOPE.md §6) |
| **URL** | https://github.com/vz-risk/VCDB |
| **Path used** | `data/json/validated/` |
| **Retrieved** | 2026-08-26 |
| **Commit pinned** | `230cf22b56a481dd1a994b21e4d94c59e2bccea9` (dated 2026-08-03) |
| **License** | Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) |
| **License file** | `LICENSE.txt` in repository root |
| **Records retrieved** | 10,596 validated incident records |
| **Local path** | `data/raw/vcdb/validated/` |

**Attribution required.** CC BY-SA 4.0 requires credit and share-alike on derivatives.
Any dataset derived from VCDB and released must carry a compatible license.

*Note:* the directory mixes `.json` and `.JSON` extensions — 550 records use the
uppercase form. Match case-insensitively or silently lose 5% of the corpus.

## 2. VERIS schema and enumerations

| | |
|---|---|
| **Role in project** | Field definitions and the enum vocabulary behind `action.*.variety` |
| **URL** | https://github.com/vz-risk/veris |
| **Files used** | `verisc.json`, `verisc-enum.json`, `verisc-labels.json`, `verisc-merged.json` |
| **Retrieved** | 2026-08-26 |
| **Commit pinned** | `45d9d7ace489b9b7bc4f1cee1daa4bf4872dfcaf` (dated 2026-06-12) |
| **License** | Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) |
| **Local path** | `data/raw/vcdb/schema/` |

## 3. VERIS → ATT&CK crosswalk

| | |
|---|---|
| **Role in project** | Evaluated as a label source and **rejected** — see `DATA_SURVEY.md` §3.3 |
| **URL** | https://github.com/vz-risk/veris, `mappings/` |
| **Files used** | `veris-1.4.1_attack-19.1-enterprise.csv`, `veris-1.4.0_attack-16.1-enterprise.csv` |
| **Retrieved** | 2026-08-26 |
| **License** | CC BY-SA 4.0 (inherited from the `veris` repository) |
| **Local path** | `data/raw/vcdb/mappings/` |

Retained for provenance only. Every substantive row is `mapping_type = related-to`,
producing a median fan-out of 2 techniques per VERIS variety and a maximum of 115, so
it cannot supply a single ground-truth technique ID. Our replacement is the
hand-curated `labels/technique_lookup.yaml`.

## 4. MITRE ATT&CK Enterprise

| | |
|---|---|
| **Role in project** | Authority for technique IDs and canonical names during labelling. **RAG: future scope, not implemented.** |
| **URL** | https://github.com/mitre-attack/attack-stix-data |
| **File used** | `enterprise-attack/enterprise-attack.json` |
| **Retrieved** | 2026-08-26 |
| **Version** | **Enterprise ATT&CK 19.2** (from the bundle's `x-mitre-collection` object) |
| **Format** | STIX 2.1 bundle, 26,086 objects |
| **License** | MITRE ATT&CK Terms of Use — free to use with attribution |
| **Terms** | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |
| **Local path** | `data/raw/attack/enterprise-attack.json` |

**Required attribution:** "© 2026 The MITRE Corporation. This work is reproduced and
distributed with the permission of The MITRE Corporation."

**Version matters.** v19.2 revoked techniques that older material still cites — for
example `T1562 Impair Defenses` is revoked in favour of `T1685 Disable or Modify
Tools`. Technique IDs in `labels/technique_lookup.yaml` are validated against this
bundle by `src/label_coverage.py`, which fails on any revoked or unknown ID. Pinning
the ATT&CK version is therefore part of reproducing this project, not a detail.

---

## 5. Base model

| | |
|---|---|
| **Role in project** | Fine-tuning base (SCOPE.md §6) |
| **Model** | `Qwen/Qwen2.5-3B-Instruct` |
| **URL** | https://huggingface.co/Qwen/Qwen2.5-3B-Instruct |
| **License** | Apache 2.0 |
| **Retrieved** | Downloaded on Kaggle at training time (kernel `l0affan/sentry-qlora-train`) |

---

## 6. Citation summary

- Verizon / VERIS Community Database contributors. *VERIS Community Database.*
  https://github.com/vz-risk/VCDB — CC BY-SA 4.0. Accessed 2026-08-26.
- MITRE. *MITRE ATT&CK Enterprise, v19.2.* https://attack.mitre.org — © 2026 The MITRE
  Corporation, reproduced with permission. Accessed 2026-08-26.
- Qwen Team, Alibaba Cloud. *Qwen2.5-3B-Instruct.* Apache 2.0.
