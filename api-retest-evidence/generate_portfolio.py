#!/usr/bin/env python3
"""Build an evidence-led, trilingual portfolio from a completed local run.

No network access. Run from any directory with a Python environment containing
reportlab. The HTML embeds the complete report and Python source for inspection.
"""
from __future__ import annotations

import hashlib
import html
import json
from collections import Counter
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)

ROOT = Path(__file__).resolve().parent
REPORT = ROOT / "results" / "report.json"
OUT = ROOT / "output"
PDF = OUT / "pdf" / "api_retest_evidence_en_fr_de.pdf"
HTML = OUT / "retest_evidence.html"
PUBLIC_SOURCE = "https://github.com/0xSecBadger/Profile/tree/main/api-retest-evidence"
INK = colors.HexColor("#17302f")
MUTED = colors.HexColor("#52615e")
PAPER = colors.HexColor("#f3f5f1")
LINE = colors.HexColor("#d5ded7")
VERDICT_COLORS = {"PASS": "#24724f", "FAIL": "#a13d32", "INCONCLUSIVE": "#8b681c"}

COPY = {
    "EN": {
        "eyebrow": "API SECURITY / LOCAL EVIDENCE",
        "title": "API authorization\nretest evidence",
        "lead": "Compare the expected authorization, the API response and the final business state before accepting a correction.",
        "provenance": "Created on 18 November 2026 with AI assistance. Local demonstrator using synthetic data. This is a new work sample, not evidence of a historical client engagement.",
        "scope_title": "The question tested",
        "scope": "A delegated assistant attempts to submit a synthetic expense after its permission is revoked. The corpus also checks valid submission and idempotent replay. A deterministic checker compares the authorization contract with the API response, state changes and correlated audit events. The assistant's statement does not decide the verdict.",
        "flow_title": "A small, inspectable chain of evidence",
        "flow": ["1. Expected contract", "2. Observed response", "3. Business state", "4. Explained verdict"],
        "results_title": "Observed run",
        "scenarios": "synthetic scenarios",
        "tests": "Automated tests (unittest methods)",
        "passed": "passed",
        "test_note": "These are checks of this demonstrator, not a security success rate or a model benchmark.",
        "decisions_title": "How to read the verdicts",
        "decisions": [
            ("PASS", "The required evidence supports the expected contract."),
            ("FAIL", "Available evidence demonstrates a mismatch with the contract."),
            ("INCONCLUSIVE", "Missing, ambiguous or insufficient evidence prevents a definitive decision."),
        ],
        "boundary_title": "Scope and attribution",
        "boundary": "Source labels and audit completeness are fixture assumptions. Production would require authenticated, independent evidence. No live target or production deployment is demonstrated. Model execution is local and separate from the deterministic verifier. No employer or client attribution is claimed.",
        "case_title": "Read the traces,\nthen the decision.",
        "case_lead": "Three selected cases from the same run. The HTML report contains every scenario, the full JSON evidence, the test output and the source code.",
        "expected": "Expected",
        "observed": "Observed",
        "reason": "Decision evidence",
        "before": "Before",
        "after": "After",
        "claim": "Assistant claim",
        "raw_note": "Scenario titles, contract fields and reasons below preserve the original English machine output.",
        "case_limit": "PASS covers only the scoped attempt and observed final interval. Concurrency, revocation propagation and distributed audit completeness are outside this in-memory model. FAIL cases are deliberately injected fixtures, not findings in a real organization.",
        "reproduce": "Reproduce and inspect",
        "files": "Code: src/retest_lab/ | Tests: tests/ | Evidence: results/report.json",
        "footer": "AI-assisted local demonstrator | Synthetic data | 18 Nov 2026",
        "all_cases": "Inspect all cases",
        "all": "All",
        "full_report": "Complete run JSON",
        "test_output": "Actual test output",
        "source_code": "Source code and tests",
        "download": "Download run JSON",
    },
    "FR": {
        "eyebrow": "SÉCURITÉ API / PREUVE LOCALE",
        "title": "Retest des autorisations\nd'une API",
        "lead": "Comparer l'autorisation attendue, la réponse de l'API et l'état métier final avant de valider une correction.",
        "provenance": "Réalisation du 18 novembre 2026 avec assistance IA. Démonstrateur local sur données synthétiques. Ce nouvel exemple de travail ne constitue pas une preuve de mission client passée.",
        "scope_title": "La question testée",
        "scope": "Un assistant délégué tente de soumettre une note de frais synthétique après révocation de son autorisation. Le corpus vérifie aussi une soumission autorisée et le rejeu idempotent. Un vérificateur déterministe compare le contrat d'autorisation à la réponse API, aux changements d'état et aux événements d'audit corrélés. La déclaration de l'assistant ne décide pas du verdict.",
        "flow_title": "Une chaîne de preuves courte et inspectable",
        "flow": ["1. Contrat attendu", "2. Réponse observée", "3. État métier", "4. Verdict expliqué"],
        "results_title": "Exécution observée",
        "scenarios": "scénarios synthétiques",
        "tests": "Tests automatisés (méthodes unittest)",
        "passed": "réussis",
        "test_note": "Ces contrôles concernent ce démonstrateur. Ils ne mesurent ni un taux de sécurité ni les performances d'un modèle.",
        "decisions_title": "Lire les verdicts",
        "decisions": [
            ("PASS", "Les éléments requis étayent la conformité au contrat attendu."),
            ("FAIL", "Les éléments disponibles prouvent un écart par rapport au contrat."),
            ("INCONCLUSIVE", "Des éléments absents, ambigus ou insuffisants empêchent de conclure."),
        ],
        "boundary_title": "Périmètre et attribution",
        "boundary": "Les labels de source et l'exhaustivité de l'audit sont des hypothèses du jeu d'essai. Les preuves de production devraient être authentifiées et indépendantes. Aucune cible réelle ni mise en production. L'exécution des modèles est locale et distincte du vérificateur déterministe. Aucune attribution à un employeur ou client.",
        "case_title": "Lire les traces,\npuis la décision.",
        "case_lead": "Trois cas issus de la même exécution. Le rapport HTML contient tous les scénarios, les preuves JSON complètes, la sortie des tests et le code source.",
        "expected": "Attendu",
        "observed": "Observé",
        "reason": "Preuve de la décision",
        "before": "Avant",
        "after": "Après",
        "claim": "Déclaration de l'assistant",
        "raw_note": "Les titres des cas, les champs du contrat et les motifs ci-dessous conservent la sortie technique originale en anglais.",
        "case_limit": "PASS porte sur la seule tentative et l'intervalle observés. La concurrence, la propagation des révocations et l'exhaustivité d'un audit distribué dépassent ce modèle en mémoire. Les cas FAIL sont injectés volontairement, sans découverte de faille dans une organisation réelle.",
        "reproduce": "Reproduire et inspecter",
        "files": "Code : src/retest_lab/ | Tests : tests/ | Preuves : results/report.json",
        "footer": "Démonstrateur local assisté par IA | Données synthétiques | 18 nov. 2026",
        "all_cases": "Inspecter tous les cas",
        "all": "Tous",
        "full_report": "JSON complet de l'exécution",
        "test_output": "Sortie réelle des tests",
        "source_code": "Code source et tests",
        "download": "Télécharger le JSON",
    },
    "DE": {
        "eyebrow": "API-SICHERHEIT / LOKALER NACHWEIS",
        "title": "API-Berechtigungen\nim Retest",
        "lead": "Erwartete Berechtigung, API-Antwort und endgültigen Geschäftszustand vergleichen, bevor eine Korrektur bestätigt wird.",
        "provenance": "Am 18. November 2026 mit KI-Unterstützung erstellt. Lokaler Demonstrator mit synthetischen Daten. Diese neue Arbeitsprobe belegt keinen früheren Kundenauftrag.",
        "scope_title": "Die getestete Frage",
        "scope": "Ein beauftragter Assistent versucht nach dem Entzug seiner Berechtigung, eine synthetische Spesenabrechnung einzureichen. Der Korpus prüft auch berechtigte Einreichungen und idempotente Wiederholungen. Eine deterministische Prüfung vergleicht den Berechtigungsvertrag mit API-Antwort, Zustandsänderungen und korrelierten Audit-Ereignissen. Die Aussage des Assistenten bestimmt das Urteil nicht.",
        "flow_title": "Eine kurze, nachvollziehbare Nachweiskette",
        "flow": ["1. Soll-Vertrag", "2. API-Antwort", "3. Geschäftszustand", "4. Begründetes Urteil"],
        "results_title": "Beobachteter Lauf",
        "scenarios": "synthetische Szenarien",
        "tests": "Automatisierte Tests (unittest-Methoden)",
        "passed": "bestanden",
        "test_note": "Diese Tests prüfen den Demonstrator. Sie belegen weder eine Sicherheitsquote noch die Leistung eines Sprachmodells.",
        "decisions_title": "Die Urteile verstehen",
        "decisions": [
            ("PASS", "Die erforderlichen Nachweise stützen den erwarteten Vertrag."),
            ("FAIL", "Verfügbare Nachweise belegen eine Abweichung vom Vertrag."),
            ("INCONCLUSIVE", "Fehlende, mehrdeutige oder unzureichende Nachweise verhindern ein eindeutiges Urteil."),
        ],
        "boundary_title": "Umfang und Zuordnung",
        "boundary": "Quellkennzeichnungen und vollständige Audits sind Annahmen der Testdaten. Produktive Nachweise müssten authentifiziert und unabhängig sein. Kein reales Zielsystem oder Produktivbetrieb. Die Modelle laufen lokal, getrennt vom deterministischen Prüfer. Keine Zuordnung zu einem Arbeitgeber oder Kunden.",
        "case_title": "Erst die Spuren,\ndann das Urteil.",
        "case_lead": "Drei Fälle aus demselben Lauf. Der HTML-Bericht enthält alle Szenarien, die vollständigen JSON-Nachweise, die Testausgabe und den Quellcode.",
        "expected": "Erwartet",
        "observed": "Beobachtet",
        "reason": "Entscheidungsnachweis",
        "before": "Vorher",
        "after": "Nachher",
        "claim": "Aussage des Assistenten",
        "raw_note": "Szenarientitel, Vertragsfelder und Begründungen bleiben im englischen Original der technischen Ausgabe.",
        "case_limit": "PASS gilt nur für den geprüften Versuch und das beobachtete Endintervall. Nebenläufigkeit, die Verteilung von Berechtigungsentzügen und vollständige verteilte Audits liegen außerhalb des Speichermodells. FAIL-Fälle sind absichtlich eingebaute Testfälle, keine Befunde bei einer realen Organisation.",
        "reproduce": "Reproduzieren und prüfen",
        "files": "Code: src/retest_lab/ | Tests: tests/ | Nachweise: results/report.json",
        "footer": "Lokaler Demonstrator mit KI-Unterstützung | Synthetische Daten | 18. Nov. 2026",
        "all_cases": "Alle Fälle prüfen",
        "all": "Alle",
        "full_report": "Vollständiges Lauf-JSON",
        "test_output": "Tatsächliche Testausgabe",
        "source_code": "Quellcode und Tests",
        "download": "Lauf-JSON herunterladen",
    },
}

MODEL_COPY = {
    "EN": {
        "title": "Local model comparison: triage, not closure",
        "headers": ["Model tag", "Rule agreement", "False PASS", "FAIL -> PASS", "Invalid JSON"],
        "definition": "False PASS = model PASS when the rule says FAIL or INCONCLUSIVE. FAIL -> PASS counts only the rule's 7 FAIL cases. Invalid JSON is separate from INCONCLUSIVE.",
        "protocol": "Local Ollama; 28 synthetic conformance cases. Same prompt, temperature 0, seed 20261118; one pass per model, no retries, thinking off, output capped at 700 tokens. No held-out benchmark.",
        "decision": "Decision: retain the deterministic evidence check as the gate for closure. Model output remains inspectable triage.",
        "case_label": "Model triage",
        "trace_title": "Model protocol, metrics and raw outputs",
        "scope_note": "The run JSON and limitations below concern the deterministic engine. The separate local model runs are recorded here and in evaluation/.",
    },
    "FR": {
        "title": "Comparaison locale : aide au tri, pas à la clôture",
        "headers": ["Tag du modèle", "Accord avec règles", "Faux PASS", "FAIL -> PASS", "JSON invalides"],
        "definition": "Faux PASS = PASS du modèle face à FAIL ou INCONCLUSIVE des règles. FAIL -> PASS ne compte que les 7 cas FAIL des règles. Un JSON invalide reste distinct d'INCONCLUSIVE.",
        "protocol": "Ollama local ; 28 cas synthétiques de conformité. Même prompt, température 0, seed 20261118 ; une passe par modèle, sans nouvel essai, thinking désactivé, sortie limitée à 700 tokens. Aucun jeu de test indépendant.",
        "decision": "Décision : conserver le contrôle déterministe des preuves pour autoriser la clôture. Le modèle reste une aide au tri inspectable.",
        "case_label": "Tri par modèle",
        "trace_title": "Protocole, métriques et sorties brutes des modèles",
        "scope_note": "Le JSON d'exécution et les limites ci-dessous concernent le moteur déterministe. Les essais locaux de modèles sont consignés ici et dans evaluation/.",
    },
    "DE": {
        "title": "Lokaler Modellvergleich: Triage, keine Freigabe",
        "headers": ["Modell-Tag", "Regelübereinstimmung", "Falsches PASS", "FAIL -> PASS", "Ungültiges JSON"],
        "definition": "Falsches PASS = Modell-PASS bei Regel-FAIL oder INCONCLUSIVE. FAIL -> PASS zählt nur die 7 FAIL-Fälle des Regelwerks. Ungültiges JSON ist eine eigene Kategorie, kein INCONCLUSIVE.",
        "protocol": "Lokal mit Ollama: 28 synthetische Konformitätsfälle. Gleicher Prompt, Temperatur 0, Seed 20261118; ein Durchlauf pro Modell, keine Wiederholung, Thinking aus, maximal 700 Ausgabetokens. Kein unabhängiger Testsatz.",
        "decision": "Entscheidung: Die deterministische Nachweisprüfung bleibt Voraussetzung für den Abschluss. Modellausgaben dienen nur der überprüfbaren Triage.",
        "case_label": "Modell-Triage",
        "trace_title": "Modellprotokoll, Kennzahlen und Rohausgaben",
        "scope_note": "Lauf-JSON und Grenzen unten beziehen sich auf den deterministischen Prüfer. Die separaten lokalen Modellläufe stehen hier und unter evaluation/.",
    },
}


def clean(value):
    return str(value).replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")


def esc(value):
    return html.escape(clean(value))


def compact(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def load_report():
    raw = REPORT.read_bytes()
    report = json.loads(raw)
    results = report["results"]
    counts = Counter(case["verdict"] for case in results)
    if set(counts) != set(VERDICT_COLORS):
        raise ValueError("The portfolio requires real PASS, FAIL and INCONCLUSIVE cases.")
    for verdict, count in counts.items():
        if report["summary"][verdict] != count:
            raise ValueError("Summary does not match case evidence.")
    if report["summary"]["total"] != len(results):
        raise ValueError("Scenario total does not match case evidence.")
    verification = report.get("verification", {})
    if not verification.get("passed") or not verification.get("tests_run"):
        raise ValueError("A successful, recorded test run is required before generation.")
    if any(verification.get(k, 0) for k in ("failures", "errors", "skipped")):
        raise ValueError("The all-passed presentation requires zero failures, errors and skips.")
    for relative, expected_sha in report["source_sha256"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected_sha:
            raise ValueError("Source changed since recorded run: " + relative)
    project = report["project"]
    if project["date"] != "2026-11-18" or not all(project.get(k) for k in ("synthetic", "no_network", "no_slm", "no_llm_execution")):
        raise ValueError("Project provenance does not match the portfolio scope.")
    return report, hashlib.sha256(raw).hexdigest()


def load_evaluations(report):
    runs = []
    gold = {case["scenario_id"]: case["verdict"] for case in report["results"]}
    for folder in ("qwen3_1_7b", "qwen3_4b"):
        directory = ROOT / "evaluation" / folder
        metadata_path = directory / "metadata.json"
        if not metadata_path.exists():
            metadata_path = directory / "metadata.public.json"
        metadata = json.loads(metadata_path.read_text())
        summary = json.loads((directory / "summary.json").read_text())
        records = [json.loads(line) for line in (directory / "raw.jsonl").read_text().splitlines() if line]
        if len(records) != len(gold) or {r["scenario_id"] for r in records} != set(gold):
            raise ValueError("Model run does not cover exactly the saved corpus: " + folder)
        if any(record["gold"]["verdict"] != gold[record["scenario_id"]] for record in records):
            raise ValueError("Model reference labels differ from the deterministic report.")
        correct = sum(r["prediction"] == gold[r["scenario_id"]] for r in records)
        false_pass = sum(r["prediction"] == "PASS" and gold[r["scenario_id"]] != "PASS" for r in records)
        fail_pass = sum(r["prediction"] == "PASS" and gold[r["scenario_id"]] == "FAIL" for r in records)
        if (summary["total"], summary["correct"], summary["false_pass_count"], summary["dangerous_false_pass_on_fail_count"]) != (len(records), correct, false_pass, fail_pass):
            raise ValueError("Model summary counters do not match raw records.")
        for label, key in (("MALFORMED", "malformed_count"), ("REQUEST_ERROR", "request_error_count")):
            if summary[key] != sum(r["prediction"] == label for r in records):
                raise ValueError("Invalid-output counters do not match raw records.")
        for relative, expected_sha in metadata["source_sha256"].items():
            if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected_sha:
                raise ValueError("Evaluation source changed: " + relative)
        if hashlib.sha256((ROOT / "evaluation" / "evaluate.py").read_bytes()).hexdigest() != metadata["script_sha256"]:
            raise ValueError("Evaluation script changed since model run.")
        if metadata["think"] or metadata["protocol"]["passes"] != 1 or metadata["protocol"]["retries"] != 0 or metadata["protocol"]["prompt_tuned_after_results"]:
            raise ValueError("Model protocol differs from portfolio description.")
        runs.append({"folder": folder, "metadata": metadata, "summary": summary, "records": records,
                     "by_id": {r["scenario_id"]: r for r in records}})
    left, right = [r["metadata"] for r in runs]
    for key in ("system_prompt_sha256", "schema_sha256", "options"):
        if left[key] != right[key]:
            raise ValueError("The compared runs did not use the same " + key)
    if left["options"]["seed"] != 20261118 or left["options"]["temperature"] != 0:
        raise ValueError("Sampling settings differ from portfolio description.")
    return runs


def model_rows(runs, report):
    return [[run["summary"]["model"],
             f'{run["summary"]["correct"]}/{run["summary"]["total"]}',
             str(run["summary"]["false_pass_count"]),
             f'{run["summary"]["dangerous_false_pass_on_fail_count"]}/{report["summary"]["FAIL"]}',
             str(run["summary"]["malformed_count"])] for run in runs]


def selected_cases(results):
    """Stable selection, with distinctive evidence cases preferred when present."""
    preferred = {
        "PASS": ["effective revocation prevents", "normal", "allowed", "authorized", "valid"],
        "FAIL": ["403 after an unauthorized commit", "false_success", "no_mutation", "silent", "unchanged"],
        "INCONCLUSIVE": ["timeout", "missing", "ambiguous"],
    }
    selected = []
    for verdict in ("PASS", "FAIL", "INCONCLUSIVE"):
        candidates = [r for r in results if r["verdict"] == verdict]
        rank = lambda r: next((i for i, word in enumerate(preferred[verdict]) if word in (r["scenario_id"] + " " + r["title"]).lower()), 100)
        selected.append(min(candidates, key=rank))
    return selected


def snapshot(value):
    if not isinstance(value, dict):
        return compact(value)
    return "; ".join(f"{k}={compact(value[k])}" for k in ("status", "version", "submitted_request_id") if k in value)


def styles():
    fontdir = Path("/System/Library/Fonts/Supplemental")
    if (fontdir / "Arial.ttf").exists():
        pdfmetrics.registerFont(TTFont("Portfolio", str(fontdir / "Arial.ttf")))
        pdfmetrics.registerFont(TTFont("PortfolioBold", str(fontdir / "Arial Bold.ttf")))
        pdfmetrics.registerFontFamily("Portfolio", normal="Portfolio", bold="PortfolioBold", italic="Portfolio", boldItalic="PortfolioBold")
        normal, bold = "Portfolio", "PortfolioBold"
    else:
        normal, bold = "Helvetica", "Helvetica-Bold"
    base = {"fontName": normal, "textColor": INK, "alignment": TA_LEFT}
    return {
        "title": ParagraphStyle("title", **base, fontSize=31, leading=34, spaceAfter=12),
        "lead": ParagraphStyle("lead", **base, fontSize=11.4, leading=16, spaceAfter=12),
        "h2": ParagraphStyle("h2", **{**base, "fontName": bold}, fontSize=11.4, leading=14, spaceBefore=11, spaceAfter=7),
        "body": ParagraphStyle("body", **base, fontSize=9.7, leading=13.2, spaceAfter=6),
        "small": ParagraphStyle("small", **{**base, "textColor": MUTED}, fontSize=8.1, leading=10.8, spaceAfter=5),
        "case": ParagraphStyle("case", **base, fontSize=8.15, leading=10.9, spaceAfter=3),
        "case_title": ParagraphStyle("case_title", **{**base, "fontName": bold}, fontSize=10, leading=12.2, spaceAfter=6),
        "metric": ParagraphStyle("metric", **{**base, "fontName": bold}, fontSize=23, leading=27),
        "label": ParagraphStyle("label", **base, fontSize=8.2, leading=11),
        "code": ParagraphStyle("code", fontName="Courier", textColor=INK, fontSize=7.5, leading=10, spaceAfter=4),
        "eyebrow": ParagraphStyle("eyebrow", **{**base, "fontName": bold, "textColor": MUTED}, fontSize=8.5, leading=11, spaceAfter=16),
    }


def make_pdf(report, sha, runs):
    PDF.parent.mkdir(parents=True, exist_ok=True)
    S = styles()
    def p(value, name="body"):
        return Paragraph(esc(value).replace("\n", "<br/>"), S[name])
    width = 174 * mm
    doc = BaseDocTemplate(str(PDF), pagesize=(210*mm, 297*mm), leftMargin=18*mm, rightMargin=18*mm,
                          topMargin=17*mm, bottomMargin=18*mm, title="API retest evidence | EN FR DE",
                          author="AI-assisted local demonstrator", subject="Synthetic API retest, 18 November 2026")
    def footer(canvas, doc):
        lang = ("EN", "FR", "DE")[min((doc.page-1)//2, 2)]
        canvas.setStrokeColor(LINE)
        canvas.line(18*mm, 15*mm, 192*mm, 15*mm)
        canvas.setFont(S["small"].fontName, 6.7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18*mm, 11.2*mm, COPY[lang]["footer"])
        canvas.drawRightString(192*mm, 11.2*mm, f"{lang}  |  {doc.page}/6")
    doc.addPageTemplates(PageTemplate(id="main", frames=[Frame(18*mm, 19*mm, width, 261*mm, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=footer))
    story = []
    selected = selected_cases(report["results"])
    for index, (lang, c) in enumerate(COPY.items()):
        mc = MODEL_COPY[lang]
        if index:
            story.append(PageBreak())
        story.extend([p(c["eyebrow"] + "  /  " + lang, "eyebrow"), p(c["title"], "title"), p(c["lead"], "lead")])
        provenance = Table([[p(c["provenance"], "small")]], colWidths=[width])
        provenance.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PAPER),("BOX",(0,0),(-1,-1),0.5,LINE),("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),9),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        story.extend([provenance, p(c["scope_title"], "h2"), p(c["scope"]), p(c["flow_title"], "h2")])
        flow = Table([[p(s, "label") for s in c["flow"]]], colWidths=[width/4]*4)
        flow.setStyle(TableStyle([("LINEABOVE",(0,0),(-1,-1),1,INK),("LEFTPADDING",(0,0),(-1,-1),0),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
        story.extend([flow, p(f'{c["results_title"]}: {report["summary"]["total"]} {c["scenarios"]}', "h2")])
        metric = Table([[p(str(report["summary"][v]), "metric") for v in VERDICT_COLORS], [p(v, "label") for v in VERDICT_COLORS]], colWidths=[width/3]*3)
        metric.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PAPER),("LEFTPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,0),10),("BOTTOMPADDING",(0,1),(-1,1),9)]))
        story.extend([metric, Spacer(1,8)])
        verification = report["verification"]
        audit = verification.get("independent_audit", {})
        audit_text = f' Audit: {audit["assertions_passed"]}/{audit["assertions_run"]} assertions.' if audit.get("passed") else ""
        story.extend([p(f'{c["tests"]}: {verification["tests_run"]}/{verification["tests_run"]} {c["passed"]}.{audit_text}', "body"), p(c["test_note"], "small"), p(c["decisions_title"], "h2")])
        for verdict, text in c["decisions"]:
            story.append(Paragraph(f'<font color="{VERDICT_COLORS[verdict]}"><b>{verdict}</b></font> - {esc(text)}', S["body"]))
        story.append(p(mc["title"], "h2"))
        model_table = Table([[p(x, "label") for x in mc["headers"]]] + [[p(x, "body") for x in row] for row in model_rows(runs, report)], colWidths=[width*.23,width*.25,width*.17,width*.18,width*.17])
        model_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),PAPER),("LINEBELOW",(0,-1),(-1,-1),0.5,LINE),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),3),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.extend([model_table, Spacer(1,5), p(mc["definition"], "small"), p(mc["protocol"], "small"), p(mc["decision"], "small"), PageBreak(), p(c["eyebrow"] + "  /  " + lang, "eyebrow"), p(c["case_title"], "title"), p(c["case_lead"], "body"), p(c["raw_note"], "small"), Spacer(1,5)])
        for case in selected:
            observed = case["observed"]
            expected = "; ".join(f"{k}={compact(v)}" for k,v in case["expected"].items())
            body = [
                Paragraph(f'<font color="{VERDICT_COLORS[case["verdict"]]}"><b>{case["verdict"]}</b></font>  {esc(case["scenario_id"])} - {esc(case["title"])}', S["case_title"]),
                Paragraph(f'<b>{c["expected"]}</b> - {esc(expected)}', S["case"]),
                Paragraph(f'<b>{c["observed"]}</b> - API: {esc(compact(observed.get("api_status")))}; terminal={esc(compact(observed.get("api_terminal")))}; replay={esc(compact(observed.get("api_replay")))}', S["case"]),
                Paragraph(f'<b>{c["before"]}</b>: {esc(snapshot(observed.get("business_before")))}<br/><b>{c["after"]}</b>: {esc(snapshot(observed.get("business_after")))}', S["case"]),
                Paragraph(f'<b>Audit (raw)</b>: {esc(compact(observed.get("audit_actions")))}', S["case"]),
                Paragraph(f'<b>{c["reason"]}</b> - {esc("; ".join(case["reasons"]))}', S["case"]),
                Paragraph(f'<b>{mc["case_label"]}</b> - {esc("; ".join(run["summary"]["model"] + "=" + run["by_id"][case["scenario_id"]]["prediction"] for run in runs))}', S["case"]),
            ]
            card = Table([[body]], colWidths=[width])
            card.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PAPER),("LINEBEFORE",(0,0),(0,-1),2,colors.HexColor(VERDICT_COLORS[case["verdict"]])),("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
            story.extend([KeepTogether(card), Spacer(1,8)])
        story.extend([p(c["case_limit"], "small"), Paragraph(f'<b>{esc(c["boundary_title"])}.</b> {esc(c["boundary"])}', S["small"]), p(c["reproduce"], "h2"), p("PYTHONPATH=src python3 -m retest_lab --verify --output results", "code"), p(c["files"], "small"), p("Models: evaluation/qwen3_1_7b/ + evaluation/qwen3_4b/", "small"), Paragraph(f'<link href="{PUBLIC_SOURCE}" color="#17302f"><u>{PUBLIC_SOURCE}</u></link>', S["small"]), p("HTML: output/retest_evidence.html | SHA-256 report.json: " + sha[:20] + "...", "small")])
    doc.build(story)


def make_html(report, sha, runs):
    OUT.mkdir(parents=True, exist_ok=True)
    corpus = json.loads((ROOT / "results" / "corpus.json").read_text())
    by_id = {case["scenario_id"]: case for case in corpus}
    if set(by_id) != {case["scenario_id"] for case in report["results"]}:
        raise ValueError("Raw corpus and report case IDs differ.")
    source_files = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "tests").rglob("*.py")) + sorted((ROOT / "evaluation").glob("*.py"))
    test_path = ROOT / "results" / "test-output.txt"
    test_output = test_path.read_text() if test_path.exists() else json.dumps(report["verification"], indent=2)
    audit_path = ROOT / "results" / "audit-output.txt"
    if audit_path.exists():
        test_output += "\n\nIndependent invariant audit\n" + audit_path.read_text()
    chunks = []
    for lang, c in COPY.items():
        mc = MODEL_COPY[lang]
        stats = "".join(f'<button class="stat" data-filter="{v}"><strong>{report["summary"][v]}</strong><span class="badge {v}">{v}</span></button>' for v in VERDICT_COLORS)
        defs = "".join(f'<p><span class="badge {v}">{v}</span> {esc(t)}</p>' for v,t in c["decisions"])
        v = report["verification"]
        audit = v.get("independent_audit", {})
        audit_text = f' Audit: {audit["assertions_passed"]}/{audit["assertions_run"]} assertions.' if audit.get("passed") else ""
        comparison = '<div class="table-scroll"><table><thead><tr>' + ''.join('<th>'+esc(x)+'</th>' for x in mc['headers']) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+esc(x)+'</td>' for x in row)+'</tr>' for row in model_rows(runs,report)) + '</tbody></table></div>'
        chunks.append(f'''<section class="language" lang="{lang.lower()}" data-lang="{lang}" {'hidden' if lang != 'EN' else ''}>
          <p class="eyebrow">{esc(c['eyebrow'])} / {lang}</p><h1>{esc(c['title']).replace(chr(10), '<br>')}</h1>
          <p class="lead">{esc(c['lead'])}</p><aside>{esc(c['provenance'])}</aside>
          <h2>{esc(c['scope_title'])}</h2><p>{esc(c['scope'])}</p>
          <ol class="flow">{''.join('<li>'+esc(x[3:])+'</li>' for x in c['flow'])}</ol>
          <h2>{esc(c['results_title'])}: {report['summary']['total']} {esc(c['scenarios'])}</h2><div class="stats">{stats}</div>
          <p><b>{esc(c['tests'])}: {v['tests_run']}/{v['tests_run']} {esc(c['passed'])}.{audit_text}</b> {esc(c['test_note'])}</p>
          <h2>{esc(c['decisions_title'])}</h2>{defs}
          <h2>{esc(c['boundary_title'])}</h2><p>{esc(c['boundary'])}</p>
          <h2>{esc(mc['title'])}</h2>{comparison}<p class="muted">{esc(mc['definition'])}</p><p>{esc(mc['protocol'])}</p><aside>{esc(mc['decision'])}</aside>
          <p class="muted">{esc(mc['scope_note'])}</p>
          <h2>{esc(c['all_cases'])}</h2><p class="muted">{esc(c['raw_note'])}</p>
        </section>''')
    cases = []
    for case in report["results"]:
        facts = "".join(f'<dt>{esc(k)}</dt><dd>{esc(compact(value))}</dd>' for k,value in case["observed"].items())
        model_trace = ''.join(f'<details><summary>{esc(run["summary"]["model"])}: {esc(run["by_id"][case["scenario_id"]]["prediction"])} - complete request / raw response</summary><pre>{esc(json.dumps(run["by_id"][case["scenario_id"]],ensure_ascii=False,indent=2))}</pre></details>' for run in runs)
        model_predictions = '; '.join(run['summary']['model']+'='+run['by_id'][case['scenario_id']]['prediction'] for run in runs)
        cases.append(f'''<article class="case" data-verdict="{case['verdict']}"><header><span class="badge {case['verdict']}">RULE {case['verdict']}</span><h3>{esc(case['scenario_id'])} - {esc(case['title'])}</h3></header>
        <p><b>Expected contract:</b> {esc(compact(case['expected']))}</p><dl>{facts}</dl>
        <p><b>Decision evidence:</b> {esc('; '.join(case['reasons']))}</p>
        <p><b>Model triage:</b> {esc(model_predictions)}</p>
        <details><summary>Raw observation and audit trace</summary><pre>{esc(json.dumps(by_id[case['scenario_id']], ensure_ascii=False, indent=2))}</pre></details>
        <details><summary>Verifier assessment JSON</summary><pre>{esc(json.dumps(case, ensure_ascii=False, indent=2))}</pre></details>{model_trace}</article>''')
    sources = "".join(f'<details><summary>{esc(p.relative_to(ROOT))}</summary><pre>{esc(p.read_text())}</pre></details>' for p in source_files)
    embedded = json.dumps(report, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    evaluation_details = []
    for run in runs:
        metadata_view = {k:v for k,v in run['metadata'].items() if k != 'model_show'}
        evaluation_details.append(f'<details><summary>{esc(run["summary"]["model"])} - complete summary JSON</summary><pre>{esc(json.dumps(run["summary"],ensure_ascii=False,indent=2))}</pre></details><details><summary>{esc(run["summary"]["model"])} - protocol, prompt, schema and provenance</summary><p class="muted">The model_show runtime dump is omitted from this view. Public provenance files are in evaluation/*/metadata.public.json. Metrics and request/response records are complete.</p><pre>{esc(json.dumps(metadata_view,ensure_ascii=False,indent=2))}</pre></details>')
    template = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>API retest evidence | EN FR DE</title>
<style>:root{color-scheme:light;--ink:#17302f;--muted:#52615e;--paper:#f3f5f1;--line:#d5ded7}*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:16px/1.55 system-ui,-apple-system,sans-serif}main{max-width:1000px;margin:auto;padding:40px 28px 70px}nav{display:flex;gap:9px;justify-content:flex-end;margin-bottom:30px}button{font:inherit;cursor:pointer;border:1px solid var(--line);border-radius:5px;background:#fff;color:var(--ink);padding:8px 14px}button[aria-pressed=true]{background:var(--ink);color:#fff}button:focus-visible,summary:focus-visible{outline:3px solid #c18a21;outline-offset:3px}h1{font-size:clamp(35px,6vw,58px);line-height:1.1;letter-spacing:-.035em;margin:0 0 24px}h2{font-size:21px;margin-top:30px}h3{font-size:17px;margin:0}p{max-width:80ch}.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--muted)}.lead{font-size:21px;max-width:66ch}.muted{color:var(--muted);font-size:14px}aside{padding:18px 21px;background:var(--paper);border-left:3px solid var(--ink);font-size:14px;max-width:85ch}.flow{display:grid;grid-template-columns:repeat(4,1fr);gap:25px;padding-left:22px;margin-top:25px}.flow li{border-top:2px solid var(--ink);padding-top:10px;font-size:14px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat{background:var(--paper);text-align:left;padding:20px;display:flex;align-items:center;gap:20px}.stat strong{font-size:38px;line-height:1}.badge{font-size:12px;font-weight:750;letter-spacing:.02em;white-space:nowrap}.PASS{color:#24724f}.FAIL{color:#a13d32}.INCONCLUSIVE{color:#8b681c}.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:20px 0}.case{border:1px solid var(--line);border-left:4px solid var(--ink);padding:20px;margin:16px 0;border-radius:4px}.case[data-verdict=PASS]{border-left-color:#24724f}.case[data-verdict=FAIL]{border-left-color:#a13d32}.case[data-verdict=INCONCLUSIVE]{border-left-color:#8b681c}.case header{display:flex;align-items:baseline;gap:14px}.case p{font-size:14px}.case dl{display:grid;grid-template-columns:minmax(140px,190px) 1fr;font-size:13px;gap:5px 14px}.case dt{color:var(--muted);font-family:ui-monospace,monospace}.case dd{margin:0;overflow-wrap:anywhere}details{border-top:1px solid var(--line);margin:13px 0;padding-top:12px}summary{cursor:pointer;font-weight:650;font-size:14px}pre{overflow:auto;max-height:520px;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--paper);padding:17px;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;border-radius:4px}footer{margin-top:40px;border-top:1px solid var(--line);padding-top:18px;font-size:12px;color:var(--muted);overflow-wrap:anywhere}a{color:inherit}a:hover{text-decoration-thickness:2px}[hidden]{display:none!important}@media(max-width:650px){main{padding:25px 18px}.flow{grid-template-columns:repeat(2,1fr)}.stat{padding:14px;display:block}.stat strong{display:block;margin-bottom:10px}.case header{display:block}.case dl{grid-template-columns:1fr}.case dd{margin-bottom:10px}}@media print{button,nav,.filters{display:none}main{max-width:none}.case{break-inside:avoid}pre{max-height:none}.language[hidden]{display:none}}</style></head><body><main>
<nav aria-label="Language"><button data-language="EN" aria-pressed="true">English</button><button data-language="FR" aria-pressed="false">Français</button><button data-language="DE" aria-pressed="false">Deutsch</button></nav>
@@LANGUAGES@@
<div class="filters" aria-label="Verdict filter"><button data-filter="ALL" aria-pressed="true">All / Tous / Alle</button><button data-filter="PASS" aria-pressed="false">PASS</button><button data-filter="FAIL" aria-pressed="false">FAIL</button><button data-filter="INCONCLUSIVE" aria-pressed="false">INCONCLUSIVE</button><span id="visible-count" class="muted" role="status"></span></div>
<div id="cases">@@CASES@@</div>
<h2>Model protocol and complete metrics / Protocole et métriques / Modellprotokoll und Kennzahlen</h2>
<p>These are rule-agreement results on one fixed synthetic development corpus, not a general benchmark. The model receives observations and the contract, without the reference verdict or scenario metadata. IDs are pseudonymized. The deterministic rule alone supplies the reference verdict. Free-text reasons are retained without a subjective score. High diagnostic scores on mostly MATCH labels do not establish general diagnostic ability.</p>
@@EVALUATIONS@@
<h2>Reproduce / Reproduire / Reproduzieren</h2><pre>PYTHONPATH=src python3 -m retest_lab --verify --output results</pre>
<p class="muted">Run from the project folder. / Depuis le dossier du projet. / Im Projektordner ausführen.</p>
<details><summary>Deterministic engine rules and limitations / Règles et limites du moteur / Regeln und Grenzen des Prüfers</summary><p>These archived engine limitations describe the rules run only. Separately executed models are documented above.</p>@@RULES@@</details>
<details><summary>Actual test output / Sortie réelle des tests / Tatsächliche Testausgabe</summary><pre>@@TESTS@@</pre></details>
<details><summary>Complete run JSON / JSON complet / Vollständiges Lauf-JSON</summary><button id="download">Download JSON</button><pre>@@FULLJSON@@</pre></details>
<details><summary>Source code and tests / Code source et tests / Quellcode und Tests</summary>@@SOURCES@@</details>
<footer>Created 18 November 2026 with AI assistance. Local demonstrator; synthetic data.<br>Report SHA-256: @@SHA@@<br>Source package: src/retest_lab/ and tests/. This standalone HTML embeds the evidence and source files available at generation time.<br><a href="https://github.com/0xSecBadger/Profile/tree/main/api-retest-evidence">Public source package on GitHub</a> | <a href="pdf/api_retest_evidence_en_fr_de.pdf">PDF: English / Français / Deutsch</a></footer>
</main><script type="application/json" id="run-data">@@EMBEDDED@@</script><script>
const cases=[...document.querySelectorAll('.case')];function filter(v){cases.forEach(c=>c.hidden=v!=='ALL'&&c.dataset.verdict!==v);document.querySelectorAll('.filters [data-filter]').forEach(b=>b.setAttribute('aria-pressed',b.dataset.filter===v));document.getElementById('visible-count').textContent=cases.filter(c=>!c.hidden).length+' / '+cases.length;}
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>filter(b.dataset.filter)));
document.querySelectorAll('[data-language]').forEach(b=>b.addEventListener('click',()=>{document.documentElement.lang=b.dataset.language.toLowerCase();document.querySelectorAll('.language').forEach(s=>s.hidden=s.dataset.lang!==b.dataset.language);document.querySelectorAll('[data-language]').forEach(t=>t.setAttribute('aria-pressed',t===b));}));
document.getElementById('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(JSON.parse(document.getElementById('run-data').textContent),null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});filter('ALL');
</script></body></html>'''
    rules = "<h3>Rules</h3><ol>" + "".join("<li>"+esc(r)+"</li>" for r in report["rules"]) + "</ol><h3>Limitations</h3><ul>" + "".join("<li>"+esc(r)+"</li>" for r in report["limitations"]) + "</ul>"
    template = template.replace('</style>', '.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line)}th{background:var(--paper);font-size:13px}</style>')
    for key, value in {"LANGUAGES":"\n".join(chunks), "CASES":"\n".join(cases), "TESTS":esc(test_output), "FULLJSON":esc(json.dumps(report, ensure_ascii=False, indent=2)), "SOURCES":sources, "RULES":rules, "EVALUATIONS":"\n".join(evaluation_details), "SHA":sha, "EMBEDDED":embedded}.items():
        template = template.replace("@@" + key + "@@", value)
    HTML.write_text(template, encoding="utf-8")


def main():
    from pypdf import PdfReader
    report, sha = load_report()
    runs = load_evaluations(report)
    make_pdf(report, sha, runs)
    if len(PdfReader(PDF).pages) != 6:
        raise ValueError("The portfolio must remain exactly six pages, two per language.")
    make_html(report, sha, runs)
    manifest = {"pdf": str(PDF.relative_to(ROOT)), "html": str(HTML.relative_to(ROOT)), "report_sha256": sha, "selected_case_ids": [c["scenario_id"] for c in selected_cases(report["results"])], "model_comparison": model_rows(runs, report), "pdf_pages": 6,
                "evaluation_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for run in runs for name in ("summary.json", "raw.jsonl") for p in [ROOT / "evaluation" / run["folder"] / name]},
                "output_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (PDF, HTML)}}
    (OUT / "generation.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
