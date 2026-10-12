# API Reference: STE-80 Brief Scorer

## Dependencies

None. Python 3.8 or later, standard library only.

## CLI Usage

```bash
python3 scripts/agent.py brief.md                      # tier from the "Audience: CISO" line
python3 scripts/agent.py --tier ciso brief.md
python3 scripts/agent.py --tier full --json report.md > score.json
```

| Option | Values | Default |
|---|---|---|
| `--tier` | `auto`, `full`, `ciso` | `auto` |
| `--json` | print the result as JSON | off |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | PASS |
| 1 | REVISE |
| 2 | Usage error or unreadable file |

## Rules Reported

| ID | Meaning |
|---|---|
| R1 | Sentence over 20 words (step or warning) or 25 words (description) |
| R2 | More than 1 instruction in a step |
| R3 | Passive voice |
| R7 | Modal or hedge: would, could, might |
| R8 | Paragraph over 6 sentences |
| R9 | Abbreviation not expanded at first use |
| R10 | Date or time not ISO 8601 with a zone, or a number written as a word |
| BAN | Banned word, for example "leverage", "robust", "significant" |
| CISO-WORDS | CISO brief over 750 words |
| CISO-TABLES | More than 1 table, more than 8 rows, or more than 200 table words |
| EMPTY | Nothing to score |

## Classes

### `Scorer(tier)`
- `run(lines)`: scores a list of lines from a markdown file
- `result()`: returns a dict with `verdict`, `percent`, `strict_zone_breaches`, `findings`, `ciso`, `caps`

## JSON Output

```json
{
  "tier": "CISO",
  "verdict": "PASS",
  "sentences": 20,
  "compliant": 20,
  "percent": 100,
  "strict_zone_breaches": 0,
  "specifics": 38,
  "ciso": {"words": 202, "tables": 1, "rows": 5, "table_words": 44},
  "caps": [],
  "findings": [],
  "advisory": []
}
```
