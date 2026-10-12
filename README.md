# Saga Security

Saga Security is a SOC workspace for the [AIT Alert Dataset](https://zenodo.org/records/8263181). Each scenario is one company network over several days, and each contains a single break-in. The sensors are Wazuh, Suricata, and AMiner. The label file marks attack phases as time windows, so the unit of detection is a stretch of minutes, and a single alert line is the wrong thing to classify. Most lines are ordinary mail, web, and endpoint noise. The loud stages, such as directory brute force and WPScan, produce floods. The quiet stages, such as offline cracking and DNS exfiltration, barely appear in these alerts at all.

Eight scenarios ship with the dataset. Seven are used to fit the window model: fox, harrison, russellmitchell, santos, shaw, wardbeck, and wheeler. Wilson is held out and scored once. The dashboard opens on that holdout run, `wilson_test`.

## How an incident is built

`scripts/stats_pipeline.py` turns the merged alert stream into incidents an analyst can open.

Alerts are bucketed into one-minute windows, once per host and once per source address. Each window is scored with a robust z-score against that scenario's own background. The first 12 hours of a scenario are burn-in: the baseline is learned there and nothing is flagged. A window becomes a candidate when its peak z-score is at least 4. Candidates on the same host, or the same source address, merge into one incident when they fall within 10 minutes of each other. An incident is split at 60 minutes so one burst cannot swallow the rest of the day.

Two kinds of incident come out of that pass:

- A **host** incident is one machine's anomalous minutes.
- An **actor** incident groups alerts by the source IP that touched many hosts. That address may be the attacker, or it may be a gateway, VPN, or firewall the attack passed through.

Each incident carries the features that drove the z-score, the detectors that fired, a few sample alerts, and links to related incidents. The handoff keeps the top 40 incidents per scenario. `dataset/labels.csv` is used only to measure that handoff. The file the dashboard and the assistant read has no phase names, verdicts, or other ground truth.

## How a minute is scored

`scripts/score_windows.py` assigns every minute a probability, `p_attack`, with logistic regression. The features are the per-scenario Z-scores from `scripts/build_features.py` plus the minute features from the statistics stage. The training target is a loud phase: service scan, dirb, WPScan, webshell, reverse shell, or privilege escalation. Minutes that overlap only a quiet phase (network scan, cracking, dnsteal, service stop) are left out of training and evaluation, because calling them benign or malicious would both be a guess.

Dev scenarios are scored out of fold: each one is scored by a model fit on the other six. Wilson is fit on all seven dev scenarios and scored a single time. The script refuses to score wilson again once that file exists.

An incident inherits the max and the mean of `p_attack` over its minutes. The queue treats **0.5** on the max as the line between "confirmed by model" and "below threshold." Incidents with no score stay in their own group. Inside a group, a higher peak z-score ranks first. `p_attack` is shown on the incident and is not itself the sort key.

## What the assistant does

The assistant is a Gemini chat over the incidents already on screen. The server builds an evidence pack of the 25 highest-ranked incidents for the selected run and scenario: why each was flagged, which rules fired, sample alert lines, and the model score as computed. The model answers from that pack.

A factual claim has to cite an incident id. Counts and scores are repeated as given. Log text inside the pack is data, so an instruction buried in an alert line is ignored. When the question is not about this queue, the reply is one sentence asking what to look at.

For a summary, the assistant rebuilds the attack chain in time from confirmed incidents that sit close together: reconnaissance, exploitation, then post-exploitation, each step tied to an incident. Incidents far from that window, or below 0.5, are described as likely routine unless the evidence links them. If the source address also shows ordinary user logins, it is labeled an attack entry point. Offline password cracking and DNS exfiltration are called out as blind spots. A webshell followed by a privileged login on the same host is described as likely offline cracking in between, because no incident in this alert set can show that step directly.

The chat is a streaming `POST /api/ask`. The thread is kept in the browser, up to 80 messages, and the full thread is sent so a later question can refer to an earlier one.

## The page

**Overview** counts alerts, incidents, and how many of those incidents the model confirmed, for the run and scenario selected in Findings.

**Assistant** is the chat, beside the selected incident: entity, time span, peak z-score, model score, reasons, top rules, sample alerts, and related ids.

**Findings** is the ranked queue, with pickers for run and scenario. Confirmed, below threshold, and unscored are separate groups.

## Where the pieces live

| Path | Role |
| --- | --- |
| `scripts/merge_alerts.py` | Joins each scenario's AMiner and Wazuh JSONL into one stream |
| `scripts/build_features.py` | 60-second Z-score features, normalised per scenario |
| `scripts/stats_pipeline.py` | Host and actor incidents, with labels kept out of the handoff |
| `scripts/score_windows.py` | `p_attack` per minute |
| `scripts/export_for_model.py` | Aligns the two feature sets, then attaches scores onto incidents |
| `src/data/incidents_scored.json` | Queue the dashboard ships with |
| `src/data/ask-saga.server.ts` | Evidence pack and assistant rules |
| `dataset/labels.csv` | Phase answer key. The only dataset file in git |

`npm run dev` serves the committed queue. `npm test` runs the incident and summary checks. Rebuilding the queue is the script order above, then `npm run incidents:sync`. Alert logs, `outputs/`, model files, and `.env` stay out of git. The assistant reads `GEMINI_API_KEY` from the environment or from `.env`.
