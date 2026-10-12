#!/usr/bin/env python3
"""STE-80 scorer for security briefs and reports.

Scores a markdown document against the STE-80 writing rules (ASD-STE100 writing rules applied to
at least 80% of sentences) and, for a CISO brief, the 2-page cap. Standard library only.

    python3 agent.py [--tier auto|full|ciso] [--json] FILE

Exit codes: 0 PASS, 1 REVISE, 2 usage error.

PASS needs all of: at least 80% of scored sentences break no rule; no breach in a strict zone
(the bottom line, numbered steps, WARNING or CAUTION lines); and for the CISO tier, 750 words or
fewer plus 1 table of 8 rows and 200 words or fewer. A document with nothing to score is REVISE.
"""

import argparse
import bisect
import json
import re
import sys

AUX = {"is", "are", "was", "were", "be", "been", "being"}
IRREGULAR = {"taken", "given", "written", "shown", "known", "seen", "done", "made", "sent",
             "found", "kept", "held", "stolen", "broken", "chosen"}
ED_NOT_VERB = {"red", "need", "speed", "feed", "seed", "bed", "shed", "embed", "hundred"}
ALLOW = set("UK US EU IT ID UTC CISO TLP IEC RED AMBER GREEN CLEAR STRICT WARNING CAUTION FULL "
            "DRAFT FINAL ISO ITIL NIST GDPR OK AM PM PASS REVISE READY NOT KNOWN YES NO".split())
STOPWORDS = {"of", "and", "the", "for", "to", "in", "on", "a", "an"}
BANNED = ["leverage", "leverages", "leveraged", "leveraging", "utilise", "utilises", "utilised",
          "utilising", "utilize", "utilizes", "utilized", "utilizing", "robust", "comprehensive",
          "holistic", "in order to", "at this point in time", "a number of", "going forward",
          "it should be noted", "best in class", "cutting edge", "state of the art",
          "sophisticated attack", "significant", "significantly", "considerable", "considerably",
          "threat landscape", "cyber hygiene", "proactive", "proactively", "ensure", "ensures",
          "ensured", "ensuring", "arguably", "generally speaking", "it depends", "in many ways"]
MONTHS = "january|february|march|april|june|july|august|september|october|november|december"
NUMBER_WORDS = ("two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|twenty|thirty|"
                "forty|fifty|hundred|thousand")
CONTROL = re.compile(r"^\s*(Document|Reference|Version|Marking|Owner|Date|Audience|Status|Review by):")
# Sentence end: terminal punctuation, optional closing quote or bracket, then whitespace. No lazy
# quantifier and no overlap, so the scan stays linear on hostile input (long punctuation runs).
SENTENCE_END = re.compile(r"[.!?][\"')]*\s+")
CHECK_THAT = re.compile(r"^ (check|confirm|verify|make sure) ")
STATE_VERB = re.compile(r" (is|are) (not )?[a-z]")


def plain(text):
    text = re.sub(r"\*\*|__|`", "", text)
    text = re.sub(r"\]\([^)]*\)", "", text).replace("[", "").replace("*", "")
    return (text.replace("e.g.", "eg").replace("i.e.", "ie").replace("etc.", "etc")
            .replace(" vs. ", " vs "))


def padded(text):
    return " " + re.sub(r"[^a-z0-9]+", " ", text.lower()) + " "


def nwords(text):
    return len([w for w in text.split() if re.search(r"[A-Za-z0-9]", w)])


def is_participle(word):
    return word in IRREGULAR or (word.endswith("ed") and len(word) > 3 and word not in ED_NOT_VERB)


def initials_match(core, text):
    words = [w for w in re.sub(r"[^a-z]+", " ", text.lower()).split() if w not in STOPWORDS]
    initials = "".join(w[0] for w in words)
    core = core.lower()
    if not initials or initials[0] != core[0]:
        return False
    k = 0
    for ch in initials:
        if k < len(core) and ch == core[k]:
            k += 1
    return k == len(core)


class Scorer:
    def __init__(self, tier):
        self.tier = "full" if tier == "auto" else tier
        self.auto = tier == "auto"
        self.findings, self.advisory = [], []
        self.sentences = self.failed = self.strict_failed = self.specifics = 0
        self.seen = set()
        self.ciso_words = self.tables = self.max_rows = self.table_words = 0

    def report(self, line, rule, detail, sentence):
        self.findings.append({"line": line, "rule": rule, "detail": detail,
                              "sentence": sentence.strip()[:120]})

    def abbreviations(self, text, line, scored):
        bad = False
        for m in re.finditer(r"[A-Z][A-Z]+s?", text):
            pre = text[m.start() - 1] if m.start() > 0 else " "
            post = text[m.end()] if m.end() < len(text) else " "
            if re.match(r"[A-Za-z0-9&-]", pre) or re.match(r"[A-Za-z0-9&-]", post):
                continue
            core = m.group()
            if re.search(r"[A-Z]s$", core):
                core = core[:-1]
            if not 2 <= len(core) <= 6 or core in ALLOW or core in self.seen:
                continue
            self.seen.add(core)
            if pre == "(" and post == ")":
                continue
            after = text[m.end():]
            if after.startswith(" (") and ")" in after and initials_match(core, after[2:after.index(")")]):
                continue
            if scored:
                self.report(line, "R9", core + " not expanded at first use", text)
                bad = True
            else:
                self.advisory.append("L%d R9 %s first appears in a table, unexpanded" % (line, core))
        return bad

    @staticmethod
    def zoneless_time(text):
        skip = False
        for m in re.finditer(r"[0-9]{2}:[0-9]{2}(:[0-9]{2})?", text):
            before = text[m.start() - 1] if m.start() > 0 else " "
            after = text[m.end():m.end() + 7]
            if skip:
                skip = False
                continue
            if before.isdigit():
                continue                       # 27001:2022 is a standard, not a time
            if re.match(r"(Z| ?UTC)", after):
                continue
            if before == "T" and re.match(r"[+-][0-9]{2}:?[0-9]{2}", after):
                skip = bool(re.match(r"[+-][0-9]{2}:", after))
                continue
            return True
        return False

    def score(self, sentence, line, strict, proc, para_index, in_list):
        sentence = sentence.strip()
        n = nwords(sentence)
        if n == 0:
            return
        self.sentences += 1
        self.specifics += len(re.findall(r"[0-9]+", sentence))
        p = padded(sentence)
        fail = False
        limit = 20 if proc else 25
        if n > limit:
            self.report(line, "R1", "%d words > %d" % (n, limit), sentence)
            fail = True
        if proc and (" and then " in p or ";" in sentence):
            self.report(line, "R2", "more than 1 instruction", sentence)
            fail = True
        if not (CHECK_THAT.match(p) and STATE_VERB.search(p)):
            words = p.split()
            for i, w in enumerate(words):
                if w not in AUX:
                    continue
                j = i + 1
                if j < len(words) and (words[j] == "not" or words[j].endswith("ly")):
                    j += 1
                if j < len(words) and is_participle(words[j]):
                    self.report(line, "R3", "passive: %s %s" % (w, words[j]), sentence)
                    fail = True
                    break
        if re.search(r" (would|could|might) ", p) or " may wish " in p or " should consider " in p:
            self.report(line, "R7", "modal or hedge", sentence)
            fail = True
        if self.abbreviations(sentence, line, True):
            fail = True
        if (re.search(r"[0-9]{1,2}/[0-9]{1,2}/[0-9]{2}", sentence)
                or re.search(r"[0-9] (%s) " % MONTHS, p) or re.search(r" (%s) [0-9]" % MONTHS, p)
                or re.search(r" [0-9]{1,2} may [0-9]", p) or re.search(r" [0-9]+(st|nd|rd|th) ", p)
                or self.zoneless_time(sentence)):
            self.report(line, "R10", "date or time not in ISO 8601 with a time zone", sentence)
            fail = True
        elif re.search(r" (%s) " % NUMBER_WORDS, p):
            self.report(line, "R10", "number written as a word", sentence)
            fail = True
        for phrase in BANNED:
            if " %s " % phrase in p:
                self.report(line, "BAN", '"%s"' % phrase, sentence)
                fail = True
                break
        if " major " in p and not re.search(r" major (incident|incidents|nonconformity|nonconformities) ", p):
            self.report(line, "BAN", '"major" as an impact word', sentence)
            fail = True
        if para_index > 6 and not in_list:
            self.report(line, "R8", "sentence %d of a paragraph (max 6)" % para_index, sentence)
            fail = True
        if fail:
            self.failed += 1
            if strict:
                self.strict_failed += 1

    def flush(self, para, state):
        if not para:
            return
        if state["appendix"] and self.tier != "ciso":
            return
        text = " ".join(t for _, t in para)
        starts, lines, pos = [], [], 0
        for ln, t in para:
            starts.append(pos)
            lines.append(ln)
            pos += len(t) + 1
        strict = state["strict"] or state["bottom"] or text.lstrip().startswith("Bottom line")
        index, begin = 0, 0
        ends = [m.end() for m in SENTENCE_END.finditer(text)] + [len(text)]
        for end in ends:
            sentence = text[begin:end]
            if nwords(sentence) > 0:
                index += 1
                line = lines[max(bisect.bisect_right(starts, begin) - 1, 0)]
                self.score(sentence, line, strict, state["proc"], index, state["list"])
            begin = end
        if self.tier == "ciso":
            self.ciso_words += nwords(text)

    def run(self, lines):
        para, state = [], {"strict": False, "proc": False, "list": False, "bottom": False, "appendix": False}
        in_fence = in_table = seen_body = False
        rows = 0

        def flush():
            nonlocal para
            self.flush(para, state)
            para = []
            state.update(strict=False, proc=False, list=False)

        def close_table():
            nonlocal in_table
            if in_table:
                self.max_rows = max(self.max_rows, rows - 1)
            in_table = False

        for number, raw in enumerate(lines, 1):
            raw = raw.rstrip("\n")
            if self.auto and number <= 25 and re.match(r"^[\s*]*Audience:[\s*]*CISO", raw):
                self.tier = "ciso"
            if re.match(r"^\s*```", raw):
                flush(); close_table(); in_fence = not in_fence
                continue
            if in_fence:
                continue
            text = plain(raw)
            if number <= 25 and not seen_body and CONTROL.match(text):
                flush(); close_table()
                continue
            if re.match(r"^\s*#", raw):
                flush(); close_table()
                heading = raw.lower()
                state["bottom"] = "bottom line" in heading
                state["appendix"] = "appendix" in heading
                if self.tier == "ciso":
                    self.ciso_words += nwords(text)
                continue
            if re.match(r"^\s*\|", raw):
                flush(); seen_body = True
                if not in_table:
                    self.tables += 1; in_table = True; rows = 0
                if re.match(r"^\s*\|[\s:|-]+$", raw):
                    continue
                rows += 1
                self.table_words += nwords(text)
                self.abbreviations(text, number, False)
                continue
            close_table()
            if not raw.strip():
                flush()
                continue
            seen_body = True
            step = re.match(r"^\s*[0-9]+[.)]\s+", raw)
            bullet = re.match(r"^\s*[-*+]\s+", raw)
            warning = re.match(r"^\s*(WARNING|CAUTION):", text)
            if step or bullet or warning:
                flush()
                state.update(proc=bool(step or warning), strict=bool(step or warning), list=True)
                para = [(number, plain(raw[(step or bullet).end():] if (step or bullet) else raw).strip())]
                continue
            para.append((number, text.strip()))
        flush(); close_table()

    def result(self):
        pct = int((self.sentences - self.failed) * 100 / self.sentences) if self.sentences else 0
        caps = []
        if self.sentences == 0:
            caps.append("EMPTY no scorable sentences")
        if self.tier == "ciso":
            if self.ciso_words > 750:
                caps.append("CISO-WORDS %d words > 750" % self.ciso_words)
            if self.tables > 1 or self.max_rows > 8 or self.table_words > 200:
                caps.append("CISO-TABLES %d tables, %d rows, %d words (max 1 table, 8 rows, 200 words)"
                            % (self.tables, self.max_rows, self.table_words))
        verdict = "PASS" if pct >= 80 and self.strict_failed == 0 and not caps else "REVISE"
        return {"tier": self.tier.upper(), "verdict": verdict, "sentences": self.sentences,
                "compliant": self.sentences - self.failed, "percent": pct,
                "strict_zone_breaches": self.strict_failed, "specifics": self.specifics,
                "ciso": {"words": self.ciso_words, "tables": self.tables, "rows": self.max_rows,
                         "table_words": self.table_words} if self.tier == "ciso" else None,
                "caps": caps, "findings": self.findings, "advisory": self.advisory}


def main():
    parser = argparse.ArgumentParser(description="Score a document against STE-80.")
    parser.add_argument("--tier", choices=["auto", "full", "ciso"], default="auto")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("file")
    args = parser.parse_args()
    try:
        with open(args.file, encoding="utf-8") as handle:
            lines = handle.readlines()
    except (OSError, UnicodeDecodeError) as error:
        print("agent.py: %s" % error, file=sys.stderr)
        return 2
    scorer = Scorer(args.tier)
    scorer.run(lines)
    result = scorer.result()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for f in result["findings"]:
            print("L%-4d %-4s %s | %s" % (f["line"], f["rule"], f["detail"], f["sentence"][:70]))
        print("\nSENTENCES: %d   COMPLIANT: %d (%d%%)   STRICT-ZONE BREACHES: %d"
              % (result["sentences"], result["compliant"], result["percent"], result["strict_zone_breaches"]))
        if result["ciso"]:
            c = result["ciso"]
            print("CISO: %d/750 words · tables %d/1 · rows %d/8 · table words %d/200"
                  % (c["words"], c["tables"], c["rows"], c["table_words"]))
        for cap in result["caps"]:
            print(cap)
        print("SPECIFICS: %d numbers or dates" % result["specifics"])
        if result["advisory"]:
            print("ADVISORY (not scored):")
            for a in result["advisory"]:
                print("  " + a)
        print("TIER: %s   VERDICT: %s" % (result["tier"], result["verdict"]))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
