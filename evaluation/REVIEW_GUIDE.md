# Independent Review Guide — Secret Leak Detector Held-Out Corpus

## Purpose

This guide lets an external security reviewer assess the ground-truth labels in
`evaluation/datasets/heldOutCorpus.ts`. The review is separate from rerunning
the scanner. Reproducing the current confusion matrix is **not** independent
validation of the labels.

## Current status

- Corpus: 40 synthetic cases (20 intended positive, 20 intended negative)
- Label author: project maintainer
- Independent reviewers: none recorded yet
- Status: **PENDING — do not describe the reported metrics as independently validated**

## Review procedure

1. Use a clean checkout and record the repository commit SHA, reviewer name or
   organization, date, and relevant security-review experience.
2. Review each case's content and context without first looking at the detector's
   output for that case.
3. Assign one of: `positive`, `negative`, or `ambiguous`. A positive case
   should represent a credential or credential-bearing value under the stated
   context. A negative case should be a benign value that should not be treated
   as a credential. Use ambiguous when the intended classification depends on
   deployment context or cannot be supported from the fixture.
4. Record a short rationale for every label. Do not silently rewrite the
   expected label; record proposed changes and their evidence.
5. Compare the independent labels with the maintainer labels. Document all
   disagreements and how they were adjudicated. Preserve the original review
   record and reviewer sign-off.
6. Only after labels are locked, run `npm ci && npm run build &&
   npm run benchmark:heldout` and compare detector outcomes with the reviewed
   labels. Record TP, FP, TN, FN and confidence intervals.

## Review record template

| Field | Value |
|---|---|
| Reviewer / organization | Pending |
| Review date | Pending |
| Repository commit SHA | Pending |
| Cases reviewed | 0 / 40 |
| Positive / negative / ambiguous labels | Pending |
| Disagreements with maintainer labels | Pending |
| Adjudication method | Pending |
| Reviewer sign-off / report URL | Pending |

## Important limitations

The corpus is small, purposive, synthetic and authored by the maintainer. Even
after external review, 40 fixtures are not sufficient to establish performance
on real production repositories or novel credential formats. A stronger
validation should include a larger independently sourced corpus, realistic
false-positive-heavy examples, adversarial encodings and file-boundary cases,
with a documented sampling process and reviewer agreement.
