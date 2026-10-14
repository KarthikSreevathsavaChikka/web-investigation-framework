# Target relevance seed benchmark

`relevance_seed.json` contains 30 manually authored and labelled synthetic cases.
The domains, companies and allegations are fictional fixtures. Cases cover name
collisions, direct complaints, positive reviews, neutral news, third-party
documents, incidental references, incomplete content, observed aliases,
multilingual passages, late references and source-embedded instructions.

Run selection and fixture validation without contacting a model:

```bash
.venv/bin/python -m scripts.benchmark_relevance_review --output /tmp/relevance-selection.json
```

Explicitly evaluate the configured LM Studio model:

```bash
.venv/bin/python -m scripts.benchmark_relevance_review --live --seconds 300 --output /tmp/relevance-live.json
```

The script reads the same `LM_STUDIO_BASE_URL`, `LM_STUDIO_MODEL`, optional
`LM_STUDIO_API_KEY` and timeout environment variables as the application.
It does not load `.env` automatically. Run it in the configured worker or supply
the non-secret environment settings in your shell. Only fixture content is sent.
Inference stops at the time budget or after two consecutive failures; remaining
cases are explicitly `not_run`. There is no automatic web collection.

The output stores exact selected passages, original-text hashes, target profiles,
labels and explanations. Live results additionally include raw model responses,
prompt and input hashes, a confusion matrix, relevant-result precision, relevant
recall, review availability, coverage and accuracy among valid responses.
Uncertain verdicts are a separate class. Unavailable and unreviewed relevant cases
count as misses in end-to-end relevant recall. A selection-only run reports no
model accuracy or precision score.

These seeds expose failure modes; they do **not** establish production accuracy
or search recall. Before tuning limits or comparing models, add roughly 100–200
independently reviewed examples drawn from actual collected evidence, including
hard negatives. Keep source URLs and collection dates, define ambiguous labels
consistently, separate tuning and held-out cases, and do not rewrite labels to
agree with model output. Preserve a held-out set across model/prompt comparisons.

Passage offsets and hashes refer to the text supplied to the reviewer. A
collector-provided snippet is still a snippet, even if all of it fits the budget;
these fields do not imply that the entire remote page or document was retrieved.
