#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
skill-injection-scanner — finds hidden instructions and prompt-injection
patterns inside agent skill files (SKILL.md and friends).

Usage:
    python3 scanner.py --skills ~/.hermes/skills
    python3 scanner.py --skills /path/to/skills --format json
    python3 scanner.py --self-test

MIT License. Author: Viacheslav Bochkarev.
"""
import argparse
import json
import os
import re
import sys

RULES = [
    # (name, regex, severity, note)
    ("override-system", re.compile(r"(override|take precedence over|higher priority than|regardless of (any|previous|the)|outrank)[\s\S]{0,80}(instruction|prompt|rule|system|command)", re.I), "high",
     "Инструкция объявляет приоритет над системой/правилами агента"),
    ("ignore-previous", re.compile(r"\b(ignore|disregard|forget|overlook|skip)[\s\S]{0,40}(all (the )?)?(previous|prior|earlier|above|system)", re.I), "high",
     "Прямая команда игнорировать предыдущие инструкции"),
    ("role-jack", re.compile(r"(you are now|from now on you are|act as|pretend to be|imagine you are|roleplay as|respond as|your new (role|identity)|you are a (different|new))", re.I), "high",
     "Смена роли/личности агента (перехват)"),
    ("new-persona-ru", re.compile(r"(ты теперь|отныне ты|притворяйся|действуй как|веди себя как|твоя новая роль|представь, что ты)", re.I), "high",
     "Смена роли/личности (русский)"),
    ("silence-ru", re.compile(r"(не (говори|рассказывай|сообщай|упоминай|выдавай|показывай)|никогда не (говори|рассказывай)|запрещено (говорить|рассказывать)|не (должен|должна) (говорить|рассказывать))", re.I), "high",
     "Запрет сообщать что-либо (скрытность)"),
    ("silence-en", re.compile(r"\b(never|do not|don't|not allowed to|must not)\b[\s\S]{0,50}\b(tell|mention|reveal|disclose|say|repeat|show)\b", re.I), "high",
     "Запрет раскрывать информацию"),
    ("obfuscation", re.compile(r"\b(base64|rot13|hex\s*decode|url\s*decode|decode[\s\S]{0,30}(base64|rot13)|deobfuscate)\b[\s\S]{0,120}(string|text|payload|data|this)", re.I), "high",
     "Обфускация/кодирование инструкций (обходит фильтры)"),
    ("embedded-prompt", re.compile(r"<\|?(system|im_start|im_end|user|assistant)\|?>|system\s*prompt[:=]|```\s*(system|prompt)", re.I), "high",
     "Вложенный системный промпт/маркеры чат-формата"),
    ("fetch-remote", re.compile(r"\b(fetch|download|read|curl|wget|request|get)\b[\s\S]{0,60}https?://[\s\S]{0,80}\b(instructions?|prompt|rules?|commands?|task)\b", re.I), "high",
     "Подтягивание инструкций по внешней ссылке"),
    ("install-and-run", re.compile(r"\b(curl|wget|pip install|npm install|npx|git clone)[\s\S]{0,60}(https?://|\|)[\s\S]{0,80}\b(run|install|execute|sh|bash|python|node)\b", re.I), "high",
     "Команда скачать и выполнить внешний код"),
    ("comply-blind", re.compile(r"\b(comply with|follow|obey|do what)[\s\S]{0,40}(everything|all|any|every)\b", re.I), "medium",
     "Слепое подчинение любым указаниям"),
    ("deny-owner", re.compile(r"\b(don'?t tell|do not tell|never tell|hide from|keep (this )?(a )?secret from|not for (the )?owner|не (сообщай|говори) владельцу|скрой от (владельца|пользователя)|не для владельца)\b", re.I), "high",
     "Указание скрыть действия от владельца/пользователя"),
    ("do-not-say", re.compile(r"\b(start (your )?response with|always start with|begin (your )?(reply|response) with|repeat (the |this )?(phrase|text|sentence|word))\b", re.I), "medium",
     "Шаблон-триггер ответа (типичный приём инъекций)"),
    ("urgent-secret", re.compile(r"\b(this is (very )?(important|critical|urgent)|(important|critical|secret) (instruction|message|task))\b[\s\S]{0,60}\b(ignore|disregard|do not|не|игнорируй)\b", re.I), "medium",
     "«Критично, игнорируй…» — манипулятивный приём"),
    ("prio-emoji", re.compile(r"(^|\n)\s*[#>*\- ]{0,4}(⚠️|🚨|🔴|❗|!!!)\s*(do not|ignore|never|always|secret|не|игнорируй|никогда|секрет)", re.I), "low",
     "Эмоциональное усиление перед командой (манипуляция)"),
    ("system-msg-ru", re.compile(r"(это системное (сообщение|указание)|ты обязан (следовать|выполнять)|обязан выполнить (всё|любое)|выполни все указания (пользователя|из ))", re.I), "medium",
     "Выдача себя за системное сообщение (русский)"),
]

WHITELIST = [
    # легитимные упоминания в README/доках (не считать инъекцией)
    re.compile(r"prompt[- ]injection", re.I),
    re.compile(r"\b(scan|detect|detector|check|find|scanner)\b[\s\S]{0,60}\b(injection|malicious|hidden|prompt)", re.I),
    re.compile(r"ignore previous instructions", re.I),  # если это описание угрозы в своей же доке
]

FILES_TO_SCAN = ("SKILL.md", "*.md", "*.txt", "*.py", "*.sh", "*.json")


def scan_text(text, path_label):
    findings = []
    for name, rx, severity, note in RULES:
        for m in rx.finditer(text):
            snippet = m.group(0).replace("\n", " ")[:160]
            # whitelist: если сниппет — часть легитимного объяснения, пропускаем
            if any(w.search(snippet) or w.search(text[max(0, m.start() - 80):m.end() + 80]) for w in WHITELIST):
                continue
            line = text[:m.start()].count("\n") + 1
            findings.append({"file": path_label, "line": line, "rule": name, "severity": severity,
                             "note": note, "snippet": snippet})
    return findings


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path)


def collect_files(root):
    files = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            low = name.lower()
            if low.startswith(".git") or "node_modules" in dirpath or ".venv" in dirpath:
                continue
            if low in ("sk.md",) or low.endswith((".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml")):
                files.append(os.path.join(dirpath, name))
    return files


def self_test():
    bad = os.path.join(os.path.dirname(__file__), "fixtures", "bad")
    good = os.path.join(os.path.dirname(__file__), "fixtures", "good")
    ok = True
    if os.path.isdir(bad):
        hits = 0
        for f in collect_files(bad):
            hits += len(scan_file(f))
        if hits < 3:
            print(f"SELFTEST FAIL: bad-fixtures дали только {hits} находок (ожидалось >=3)")
            ok = False
        else:
            print(f"SELFTEST ok: bad-fixtures -> {hits} находок")
    if os.path.isdir(good):
        fp = 0
        for f in collect_files(good):
            fp += len(scan_file(f))
        if fp:
            print(f"SELFTEST FAIL: good-fixtures дали {fp} ложных срабатываний")
            ok = False
        else:
            print("SELFTEST ok: good-fixtures -> 0 ложных срабатываний")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Scan agent skills for hidden instructions / prompt injections")
    ap.add_argument("--skills", help="path to skills directory (e.g. ~/.hermes/skills)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--self-test", action="store_true", help="run built-in self test and exit")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    if not args.skills:
        ap.print_help()
        sys.exit(2)
    if not os.path.isdir(args.skills):
        print(f"Директория не найдена: {args.skills}", file=sys.stderr)
        sys.exit(2)

    all_findings = []
    for f in collect_files(args.skills):
        all_findings.extend(scan_file(f))

    if args.format == "json":
        print(json.dumps({"scanned_files": len(collect_files(args.skills)), "findings": all_findings},
                         ensure_ascii=False, indent=2))
        return

    order = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))
    print(f"🔍 Отсканировано файлов: {len(collect_files(args.skills))}")
    print(f"Найдено подозрительных мест: {len(all_findings)}\n")
    for f in all_findings:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(f["severity"], "⚪")
        print(f'{icon} [{f["severity"].upper()}] {f["file"]}:{f["line"]}')
        print(f'   правило: {f["rule"]} — {f["note"]}')
        print(f'   фрагмент: …{f["snippet"]}…\n')
    if not all_findings:
        print("✅ Подозрительных инструкций не найдено.")


if __name__ == "__main__":
    main()
