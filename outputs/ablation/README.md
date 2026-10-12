# Ablation: does the stats stage help his model? (`scripts/ablation_loso.py`)
Setup: leave-one-scenario-out over the 7 dev scenarios (wilson never loaded); every arm uses his logreg pipeline (`train_supervised.make_model("logreg")`: log1p, L2 logistic regression, balanced class weights), target `is_burst`, his `usable` mask (minutes overlapping only quiet phases dropped from fit and evaluation), his `evaluate()` with a top-1% alert budget per scenario. Arms: `his` = his 35 Z-score features; `st` = the 26 `st_` minute features from `export_for_model.py export` (max over hosts of the stats-stage robust z-scores, clipped at 0); `his+st` = both.
| arm | features | mean AP | worst AP | mean recall@1% | phases caught | false pos @1% |
|---|---|---|---|---|---|---|
| his | 35 | 0.828 | 0.637 | 0.862 | 41 / 42 | 394 |
| his+st | 61 | 0.907 | 0.804 | 0.954 | 40 / 42 | 390 |
| st | 26 | 0.901 | 0.706 | 0.951 | 40 / 42 | 391 |
Chosen model: `his+st` (decided on this table only, before wilson was scored). Per-fold numbers: `ablation_results.csv`; per-phase best-minute ranks: `ablation_phase_ranks.csv`.
Caveats: only 112 positive minutes across the 7 folds, so per-fold AP is noisy and the gain is directional, not conclusive; positives are the 6 loud phases only (network_scans, cracking, dnsteal, service_stop are neither scored nor evaluated by this target); wheeler is the one fold that gets worse with `st` (AP 0.994 to 0.913, one phase drops out of the top 1%); the gain is mostly substitution, since `st` alone nearly matches `his+st`.
