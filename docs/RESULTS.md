# Sample run results

Generated: 2026-10-03T15:19:57  
Mode: **ollama / qwen3:1.7b**  
Synthetic data only. Heuristic risk scores, not validated. These are single runs, not a benchmark.

| Sample | Risk before | Risk after | Edits | AI clues before → after | Rejected claims (b/a) | Time b/a (s) |
|---|---|---|---|---|---|---|
| s1 | HIGH (18) | HIGH (18) | 5 | 2 → 8 | 5/0 | 149.0/122.3 |
| s2 | HIGH (20) | HIGH (11) | 5 | 5 → 4 | 0/0 | 91.8/108.2 |
| s3 | HIGH (24) | HIGH (13) | 5 | 6 → 6 | 0/0 | 79.5/108.4 |

## Sample 1 — Photographer (the Rahul example)

**Anonymized:**

> [NAME] is 25 years old and lives in Chandigarh. He works at ABC Hospital and won the photography competition in 2024. You can reach him at [EMAIL] or [PHONE].

**Hardened:**

> [NAME] is in their 20s and lives in Northern India. He works at a hospital and won a competition in the mid 2020s. You can reach him at [EMAIL] or [PHONE].

**Remaining items after hardening:**

- other: "You can reach him at [EMAIL] or [PHONE]." (ai)
- achievement: "He works at a hospital and won a competition in the mid 2020s." (ai)
- employer: "He works at a hospital" (ai)
- date_event: "won a competition in the mid 2020s" (ai)
- location: "lives in Northern India" (ai)
- other: "[EMAIL] or [PHONE]" (ai)
- role: "works at a hospital" (ai)
- age: "is in their 20s" (ai)

## Sample 2 — Interview transcript

**Anonymized:**

> Interview 07. Participant: [NAME]. I'm 34 and I teach chemistry at St. Anne's School in Coimbatore. I started teaching in 2019, after moving back from Pune. Last year my students won the state science fair and it made the local paper. My husband runs a small bakery near Race Course Road, so our mornings are always busy.

**Hardened:**

> Interview 07. Participant: [NAME]. I'm in my 30s and I teach chemistry at a school in Southern India. I started teaching in the late 2010s, after moving back from Western India. Last year my students won the state science fair and it made the local paper. My husband runs a small bakery near Race Course Road, so our mornings are always busy.

**Remaining items after hardening:**

- location: "I'm in my 30s and I teach chemistry at a school in Southern India." (ai)
- date_event: "I started teaching in the late 2010s, after moving back from Western India." (ai)
- achievement: "Last year my students won the state science fair and it made the local paper." (ai)
- relationship: "My husband runs a small bakery near Race Course Road, so our mornings are always busy." (ai)

## Sample 3 — Support ticket

**Anonymized:**

> Ticket #4821. Customer [NAME], a 41-year-old senior orthopaedic surgeon at Sunrise Hospital in Ludhiana, reports that his account was locked after 3 failed logins. He joined in March 2022 and works night shifts every weekend. Contact: [EMAIL] or [PHONE].

**Hardened:**

> Ticket #4821. Customer [NAME], a 40-something surgeon at a hospital in Northern India, reports that his account was locked after 3 failed logins. He joined in the early 2020s and works night shifts every weekend. Contact: [EMAIL] or [PHONE].

**Remaining items after hardening:**

- location: "Customer [NAME], a 40-something surgeon at a hospital in Northern India, reports that his account was locked after 3 failed logins." (ai)
- other: "Contact: [EMAIL] or [PHONE]." (ai)
- date_event: "He joined in the early 2020s and works night shifts every weekend." (ai)
- employer: "Customer [NAME], a 40-something surgeon at a hospital in Northern India" (ai)
- role: "works night shifts every weekend" (ai)
- date_event: "joined in the early 2020s" (ai)
