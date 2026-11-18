# Independent review packet workflow

This directory provides a generator for an external, process-based blind review
of the 40-case held-out evaluation corpus.

## Generate a reviewer packet

From the repository root:

```bash
npm ci
npm run review:packet
```

The command creates two files in a private temporary directory outside the
repository:

- `blind-review-packet.json`: 40 shuffled cases with neutral IDs, file/line
  context, and fixture content only.
- `review-worksheet-<packet-id>.csv`: blank classification and rationale
  fields for the reviewer.

The generated packet excludes the maintainer's expected labels, detector rule
names, source case IDs, descriptions, and scanner outcomes. Each run uses a
fresh random order and packet ID. To choose a specific output path, use:

```bash
npm run review:packet -- --output /absolute/path/blind-review-packet.json
```

The worksheet is written alongside the packet. Keep both generated files out
of Git; the fixture strings are synthetic test values and some intentionally
match credential detectors.

## Reviewer eligibility and return requirements

Ask a reviewer who is not the project maintainer, has not contributed to the
detector rules or held-out labels, and can disclose relevant security-review
experience and conflicts of interest. They should review the supplied packet
before seeing the labelled source file or detector output.

For every case, the reviewer must return exactly one classification:
`positive`, `negative`, or `ambiguous`, plus a concise rationale. The
reviewer should preserve the packet ID, report disagreements with the author's
labels only after submitting the initial classifications, and sign/date the
review record.

Do not close issue #46 or claim independent validation until the external
review, disagreement adjudication, and reviewer sign-off are recorded.

## Blinding limitation

The repository is public, and the author's original labels remain visible in
`evaluation/datasets/heldOutCorpus.ts`. The packet hides those labels from the
review worksheet but cannot technically prevent a reviewer from discovering
the source labels. This is therefore a process-based blind review, not a
controlled or access-isolated blinded study. Send the packet separately and
ask the reviewer not to inspect the labelled source or benchmark output before
submitting the initial worksheet.
