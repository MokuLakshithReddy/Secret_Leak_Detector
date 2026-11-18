# Held-out evaluation report schema

This document describes the data contract for
`evaluation/reports/held_out_results.json`. The report's `schemaVersion` is
independent of the extension/npm package version.

## Version history

### 1.0

The original report included:

- `schemaVersion` and `description`
- `methodology` with corpus separation, labelling process, runtime/platform,
  command, and reproducibility details
- `expectedResults` with the confusion matrix and point metrics
  (`totalCases`, `tp`, `fp`, `tn`, `fn`, `precision`, `recall`,
  `f1`, and `fpr`)
- `independentReproduction` instructions and status

### 1.1

Version 1.1 is an additive change. It retains the 1.0 fields and adds:

| JSON path | Type | Meaning |
|---|---|---|
| `methodology.labelingStatus` | string | Explicitly records that the current labels are author-assigned and not independently reviewed |
| `methodology.samplingLimitations` | string | Explains purposive synthetic sampling and what the intervals cannot correct for |
| `methodology.independentReviewStatus` | string | Records the pending third-party review state |
| `expectedResults.confidenceIntervals95.precision` | object | Wilson lower/upper interval for precision |
| `expectedResults.confidenceIntervals95.recall` | object | Wilson lower/upper interval for recall |
| `expectedResults.confidenceIntervals95.fpr` | object | Wilson lower/upper interval for false-positive rate |
| `expectedResults.confidenceIntervalMethod` | string | Names the two-sided 95% Wilson score method and z-score |

The `confidenceIntervals95` objects contain numeric `lower` and `upper`
bounds in the inclusive range [0, 1].

## Consumer migration

Consumers reading version 1.0 should:

1. Accept `schemaVersion: "1.1"` in addition to `"1.0"`.
2. Continue reading the existing point metrics and confusion-matrix fields.
3. Treat the new provenance and confidence-interval fields as additional
   metadata; older consumers may ignore them, but should not silently describe
   the report as independently validated.
4. Use the new intervals when presenting precision, recall, or false-positive
   rate. Do not interpret a perfect point estimate on 20 positive and 20
   negative cases as a production guarantee.

## JSON number semantics

JSON has one numeric data type; it does not distinguish integers from
floating-point numbers. JavaScript serializes a numeric value such as `1.0`
as `1`, and both are the same JSON number. Consumers should validate these
metrics as JSON `number` values and must not depend on the textual presence of
a decimal point. The precision value changing from a textual `1.0` to `1`
is therefore not a JSON type change.

## Evidence limitations

Schema version 1.1 does not indicate independent validation. The 40 held-out
cases are synthetic and author-labelled. External review, disagreement
adjudication, and reviewer sign-off remain outstanding; see
[`evaluation/REVIEW_GUIDE.md`](../REVIEW_GUIDE.md).
