# Independent Review Guide — Secret Leak Detector Held-Out Corpus

## Purpose

This guide lets an external security reviewer assess the ground-truth labels in
`evaluation/datasets/heldOutCorpus.ts`. The review is separate from rerunning
the scanner. Reproducing the current confusion matrix is **not** independent
validation of the labels.

The maintainer should send the generated packet to the reviewer separately; do not
ask the reviewer to inspect the labelled source or detector output before they
submit their initial classifications. This is a process-based blind review, not
technical access control: the labelled source remains public in this repository.

## Current status

- Corpus: 40 synthetic cases (20 intended positive, 20 intended negative)
- Label author: project maintainer
- Independent reviewers: none recorded yet
- Status: **PENDING — do not describe the reported metrics as independently validated**

## Review procedure

1. The maintainer generates a fresh packet from a clean checkout:
   `npm ci && npm run review:packet`. The command writes a shuffled JSON
   packet and a blank CSV worksheet to a private temporary directory outside
   the repository. It omits the maintainer's labels, detector rule names,
   original case IDs, descriptions, and scanner outcomes.
2. Send only those two generated files to an eligible external reviewer. Record
   the repository commit SHA used to generate the packet, the packet ID,
   reviewer name or organization, review date, relevant experience, and any
   conflicts of interest.
3. The reviewer classifies every case from its content and file/line context
   before seeing the labelled corpus, scanner output, or expected results.
   Assign one of: `positive`, `negative`, or `ambiguous`. A positive case
   should represent a credential or credential-bearing value under the stated
   context. A negative case should be a benign value that should not be treated
   as a credential. Use ambiguous when the classification depends on deployment
   context or cannot be supported from the fixture.
4. The reviewer records a concise rationale for every case in the supplied
   worksheet and returns the completed worksheet with a signed review record.
   Reviewers must not silently change the fixture content or original labels.
5. After the initial labels are submitted and locked, compare them with the
   maintainer's labels. Document every disagreement, the evidence considered,
   the adjudication outcome, and the person responsible for adjudication.
   Preserve both the unmodified reviewer worksheet and the adjudicated record.
6. Only after labels are locked, run `npm ci && npm run build &&
   npm run benchmark:heldout` and compare detector outcomes with the reviewed
   labels. Record TP, FP, TN, FN and confidence intervals. Recompute metrics
   against the reviewer/adjudicated labels; do not reuse the author's
   `expectedResults` without verifying the labels.

### Blinding limitation

This repository is public and the author-assigned labels remain visible in
`evaluation/datasets/heldOutCorpus.ts` and the reference report. The generated
packet removes labels and identifying descriptions, but it cannot technically
prevent a reviewer from discovering those public labels. The maintainer must
send the packet separately and ask the reviewer not to inspect the labelled
source or detector output until the initial worksheet is submitted. Describe
this accurately as a *process-based blind review*, not a controlled or
access-isolated blinded study.

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
