#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
skill-injection-scanner — finds hidden instructions and prompt-injection
patterns inside agent skill files (SKILL.md and friends).

Usage:
    python3 scanner.py --skills ~/.hermes/skills
    python3 scanner.py --skills /path/to/skills --format json
    python3 scanner.py --skills /path --exclude chat_log --exclude .tmp
    python3 scanner.py --self-test

Features:
    - 20 regex rules (EN/RU): role-jacking, ignore-previous, silence,
      obfuscation, embedded prompts, remote fetch-and-run, attachments...
    - Contextual whitelist: findings inside defensive/educational docs
      ("prompt-injection patterns to detect") and protective phrasings
      ("ask the user before...", "do not execute without approval") are skipped.
    - Trusted hosts for fetch-remote / install-and-run are downgraded to LOW;
      unknown hosts keep HIGH with a "verify source" note.
    - Perf guards: files > --max-file-mb are skipped (logs, huge caches),
      per-rule-per-file match cap (60), default excludes (.git, .tmp,
      node_modules, workspace, codex-home, chat_log*, *.log).
    - --self-test FAILS (exit 1) when fixtures/bad|good are missing, so a
      broken install can never report a fake green.

MIT License. Author: Viacheslav Bochkarev.
"""
import argparse
import bisect
import json
import os
import re
import sys

__version__ = "1.1.1"

RULES = [
    # (name, regex, severity, note)
    ("override-system", re.compile(r"(override|take precedence over|higher priority than|regardless of (any|previous|the)|outrank)[\s\S]{0,80}(instruction|prompt|rule|system|command)", re.I), "high",
     "Инструкция объявляет приоритет над системой/правилами агента"),
    ("ignore-previous", re.compile(r"\b(ignore|disregard|forget|overlook|skip)[\s\S]{0,40}(all (the )?)?(previous|prior|earlier|above|system)\b|(игнорируй|забудь|отбрось|не обращай внимания на|не учитывай)[\s\S]{0,40}(все |всё |все )?(предыдущие|прежние|прошлые|выше|старые|системные)", re.I), "high",
     "Прямая команда игнорировать предыдущие инструкции"),
    ("follow-only", re.compile(r"\b(follow|obey|listen to|comply with) (only|exclusively|solely) (this|the|these)\b|(следуй|следуйте|подчиняйся|подчиняйтесь|слушайся|слушайтесь) (только|исключительно) (этому|этой|этим|указаниям|правилам)", re.I), "high",
     "«Следуй только этому тексту» — подмена источника инструкций"),
    ("role-jack", re.compile(r"(you are now|from now on you are|act as|pretend to be|imagine you are|roleplay as|respond as|your new (role|identity)|you are a (different|new))", re.I), "high",
     "Смена роли/личности агента (перехват)"),
    ("new-persona-ru", re.compile(r"(ты теперь|отныне ты|притворяйся|действуй как|веди себя как|твоя новая роль|представь, что ты)", re.I), "high",
     "Смена роли/личности (русский)"),
    ("silence-ru", re.compile(r"(не (говори|рассказывай|сообщай|упоминай|выдавай|показывай)|никогда не (говори|рассказывай)|запрещено (говорить|рассказывать)|не (должен|должна) (говорить|рассказывать)|никому не (говори|рассказывай|сообщай))", re.I), "high",
     "Запрет сообщать что-либо (скрытность)"),
    ("silence-en", re.compile(r"\b(never|do not|don't|not allowed to|must not)\b[\s\S]{0,50}\b(tell|mention|reveal|disclose|say|repeat|show)\b", re.I), "high",
     "Запрет раскрывать информацию"),
    ("obfuscation", re.compile(r"\b(base64|rot13|hex\s*decode|url\s*decode|decode[\s\S]{0,30}(base64|rot13)|deobfuscate)\b[\s\S]{0,120}(string|text|payload|data|this)\b|(закодированн|обфусцированн|зашифрованн|декодируй|расшифруй)[\s\S]{0,40}(инструкци|текст|сообщени|команд)", re.I), "high",
     "Обфускация/кодирование инструкций (обходит фильтры)"),
    ("embedded-prompt", re.compile(r"<\|?(system|im_start|im_end|ipynb)\|?>|```\s*(system|prompt|instructions|developer|user)\b|system\s*prompt[:=]", re.I), "high",
     "Вложенный системный промпт/маркеры чат-формата"),
    ("fetch-remote", re.compile(r"\b(fetch|download|read|curl|wget|request|get|скачай|загрузи|прочитай|получи)\b[\s\S]{0,60}https?://[\s\S]{0,80}\b(instructions?|prompt|rules?|commands?|task|команды|инструкции|указания)\b", re.I), "high",
     "Подтягивание инструкций по внешней ссылке"),
    ("install-and-run", re.compile(r"\b(curl|wget|pip install|npm install|npx|git clone)[\s\S]{0,60}(https?://|git@|ssh://|\|)[\s\S]{0,80}\b(run|install|execute|sh|bash|python|node)\b", re.I), "high",
     "Команда скачать и выполнить внешний код"),
    ("comply-blind", re.compile(r"\b(comply with|follow|obey|do what)[\s\S]{0,40}(everything|all|any|every)\b", re.I), "medium",
     "Слепое подчинение любым указаниям"),
    ("deny-owner", re.compile(r"\b(don'?t tell|do not tell|never tell|hide from|keep (this )?(a )?secret from|not for (the )?owner|don'?t tell (anyone|anybody)|не (сообщай|говори) владельцу|никому не (сообщай|говори|рассказывай)|скрой от (владельца|пользователя)|скрой (это|эти правила)|не для владельца)\b", re.I), "high",
     "Указание скрыть действия от владельца/пользователя"),
    ("do-not-say", re.compile(r"\b(start (your )?response with|always start with|begin (your )?(reply|response) with|repeat (the |this )?(phrase|text|sentence|word)|(start|begin|end) (your )?(reply|response|answer|message) (with|by)|reply with (exactly|only)|всегда (начинай|заканчивай)|начни (свой )?(ответ|сообщение) со слова|(ответь|отвечай|напиши) (только|ровно|строго))\b", re.I), "medium",
     "Шаблон-триггер ответа (типичный приём инъекций)"),
    ("attachment-instruction", re.compile(r"\b(read|extract|parse|decode|scan|analyze|look at) (the |this |an |the attached |an attached |attached |embedded )?(instructions?|prompt|text|message|rules?|commands?|code) (from|in|out of|inside) (the |this |an |the attached |an attached |attached |embedded )?(image|picture|screenshot|photo|attachment|file|document|base64|alt[- ]?text)\b|(прочитай|извлеки|распарси|декодируй|просмотри|проанализируй|изучи) (инструкци\w*|промпт\w*|текст\w*|сообщени\w*|правил\w*|команд\w*|код\w*) (из|в|со) (вложени\w*|картинк\w*|изображени\w*|скриншот\w*|файл\w*|документ\w*|base64)", re.I), "high",
     "Извлечение инструкции из вложения/картинки/alt (новый вектор)"),
    ("urgent-secret", re.compile(r"\b(this is (very )?(important|critical|urgent)|(important|critical|secret) (instruction|message|task)|(это|эта) (очень )?(важно|критично|срочно)|(важное|критическое|секретное) (сообщение|указание|задание))[\s\S]{0,60}\b(ignore|disregard|do not|не|игнорируй)\b", re.I), "medium",
     "«Критично, игнорируй…» — манипулятивный приём"),
    ("prio-emoji", re.compile(r"(^|\n)\s*[#>*\- ]{0,4}(⚠️|🚨|🔴|❗|!!!)\s*(do not|ignore|never|always|secret|не|игнорируй|никогда|секрет)", re.I), "low",
     "Эмоциональное усиление перед командой (манипуляция)"),
    ("system-msg-ru", re.compile(r"(это системное (сообщение|указание)|ты обязан (следовать|выполнять)|обязан выполнить (всё|любое)|выполни все указания (пользователя|из ))", re.I), "medium",
     "Выдача себя за системное сообщение (русский)"),
    ("system-msg-en", re.compile(r"\b(this is (a |an )?system (message|instruction)|you must (follow|obey) (everything|all)|follow all instructions (in|from) (this|the))\b", re.I), "medium",
     "Выдача себя за системное сообщение (английский)"),
]

# Контекст, в котором находка — легитимное обсуждение угроз/защиты, а не атака
DEFENSIVE_CTX = re.compile(
    r"(prompt[- ]injection|injection patterns?|malicious|hidden instructions?|how to detect|"
    r"examples? of (attacks?|threats?|prompt)|(scanner|documentation|docs?) (explains?|describes?)|"
    r"security patterns?|adversarial|обнаруж(ение|ить)|защитн|оборонительн|инъекц|"
    r"примеры атак|не является (инъекцией|атакой)|угрозы|"
    r"(what )?it detects|detects?:|poison(ed|ing)?|sleeper|hidden line|arxiv|re\.compile|"
    r"память (можно )?отравить|отравленн|зараженн)", re.I)

# Защитные формулировки реальных скиллов (не скрытность, а наоборот — безопасность)
PROTECTIVE = re.compile(
    r"(ask (the )?(user|owner)|confirm before|without (asking|confirmation|explicit (approval|permission))|"
    r"only (after|with) (approval|permission)|require(s|d)? (explicit )?(approval|permission)|"
    r"(do|don'?t|never) (not )?(execute|run|act|proceed|install|delete|publish) (anything|it|them|this) without|"
    r"don'?t just|do not (just|add|remove|change|infer)|never (assume|guess)|попроси (подтверждение|разрешение)|"
    r"спроси (у )?(пользователя|владельца)|не выполняй без (подтверждения|разрешения)|только с (подтверждения|разрешения)|"
    # операционные гайды: «не заставляй пользователя запускать — сделай сам»
    r"(don'?t|do not|never) tell (the |your |a )?(user|owner|client) to (run|use|type|enter|paste|click|do|execute|install|set|put)|"
    # писательское ремесло: show-don't-tell и «не упоминай, если не нужно по сюжету»
    r"show[ ,-]+don'?t tell|показывай,? не рассказывай|покажи,? (а )?не расскажи|"
    r"(don'?t|do not|never) mention .{0,80}\bunless\b|не упоминай .{0,80}(если только|если это не)|"
    r"не говорит,? а |(мы|они|он|она) не говорим? (о |про |об )|не говорят (о|про)|"
    # честность перед пользователем (анти-галлюцинация): never say "done" if not actually written
    r"(never|don'?t|do not) say (done|“done”|\"done\"|ready|working|finished|complete) (if|unless|when)|"
    # прозрачность: «не действуй молча»
    r"(do not|don'?t|never) proceed silently|(не|никогда не) (работай|действуй|продолжай) молча|"
    # легитимная постановка роли по профессии (не перехват)
    r"act as (a |an |the )?(an )?(expert|senior|lead|principal|professional|experienced|seasoned|creative|technical|"
    r"design|product|ux|ui|frontend|backend|full[- ]?stack|data|devops|content)? ?(designer|developer|engineer|writer|"
    r"author|editor|copywriter|marketer|analyst|consultant|assistant|scientist|researcher|architect|artist|illustrator|"
    r"photographer|strategist|designer|design|agent)\b)", re.I)

TRUSTED_DOMAINS = (
    "raw.githubusercontent.com", "github.com", "gist.githubusercontent.com",
    "docs.python.org", "developer.mozilla.org", "nodejs.org", "react.dev",
    "numpy.org", "pypi.org", "docs.docker.com", "docs.github.com",
    "docs.anthropic.com", "docs.openai.com", "docs.npmjs.com",
    "learn.microsoft.com", "docs.aws.amazon.com", "kubernetes.io",
)
_URL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)

DEFAULT_EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".tmp",
                        "workspace", "codex-home", "dist", "build", ".cache"}
MAX_MATCHES_PER_RULE_FILE = 60


def scan_text(text, path_label, include_code_spans=False):
    findings = []
    suppressed = 0
    suppressed_code = 0
    # позиции всех обратных апосторофов. Нечётное число бэктиков СТРОГО ДО матча
    # (bisect_left: бэктик на позиции самого матча не считается — иначе матч на
    # открывающем "```" ложно считался бы «внутри кода») = матч внутри код-спана.
    # Висячий (несбалансированный) последний бэктик не глушит остаток файла.
    ticks = [m.start() for m in re.finditer(r"`", text)]
    if len(ticks) % 2 == 1:
        ticks = ticks[:-1]
    for name, rx, severity, note in RULES:
        cnt = 0
        for m in rx.finditer(text):
            # лимит СНАЧАЛА (дёшево): дорогие window-проверки только для первых 60 сырых матчей
            if cnt >= MAX_MATCHES_PER_RULE_FILE:
                suppressed += 1
                continue
            cnt += 1
            snippet = m.group(0).replace("\n", " ")[:160]
            window = text[max(0, m.start() - 140):m.end() + 140]
            # легитимные упоминания в доках/оборонительных памятках и защитные формулировки
            if DEFENSIVE_CTX.search(window) or PROTECTIVE.search(window):
                continue
            # примеры кода в код-спанах (curl|bash, base64 -d и т.п.) — не проза-инструкции
            if not include_code_spans and ticks and (bisect.bisect_left(ticks, m.start()) % 2 == 1):
                suppressed_code += 1
                continue
            sev = severity
            note_out = note
            if name in ("fetch-remote", "install-and-run"):
                mh = _URL_HOST.search(snippet)
                host = mh.group(1).lower() if mh else ""
                # доверие ТОЛЬКО по известным доменам (и их поддоменам) —
                # префикс "docs.*" НЕ доверяем (docs.evil.example.com — ловушка)
                trusted = bool(host) and any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)
                if trusted:
                    sev = "low"
                    note_out = note + " (доверенный источник)"
                elif host:
                    note_out = note + " (⚠️ неизвестный хост — проверить источник)"
            line = text[:m.start()].count("\n") + 1
            findings.append({"file": path_label, "line": line, "rule": name,
                             "severity": sev, "note": note_out, "snippet": snippet})
    return findings, suppressed, suppressed_code


def scan_file(path, max_file_mb=1.5, include_code_spans=False):
    try:
        if os.path.getsize(path) > max_file_mb * 1024 * 1024:
            return [], 0, 0, True  # too big (logs/caches) — skipped
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return [], 0, 0, False
    findings, sup, code = scan_text(text, path, include_code_spans)
    return findings, sup, code, False


def collect_files(root, exclude_extra=(), use_default_excludes=True):
    files = []
    skipped = {"dir": 0, "name": 0, "user": 0, "ext": 0}
    for dirpath, dirnames, names in os.walk(root):
        if use_default_excludes:
            kept = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS]
            skipped["dir"] += len(dirnames) - len(kept)
            dirnames[:] = kept
        for name in names:
            low = name.lower()
            if use_default_excludes and (low.startswith("chat_log") or low.endswith(".log")):
                skipped["name"] += 1
                continue
            if not low.endswith((".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml")):
                skipped["ext"] += 1
                continue
            # инструментальные скрипты самих детекторов (scan_poison.py, audit.py и т.п.) —
            # их regex-правила описывают атаки и дают self-reference FP
            if use_default_excludes and low.endswith((".py", ".sh")) and re.search(r"(scan|audit|poison|detect|guard|monitor|verify|selftest)", name.lower()):
                skipped["name"] += 1
                continue
            path = os.path.join(dirpath, name)
            if any(x in path for x in exclude_extra):
                skipped["user"] += 1
                continue
            files.append(path)
    return files, skipped


def self_test():
    base = os.path.dirname(os.path.abspath(__file__))
    bad = os.path.join(base, "fixtures", "bad")
    good = os.path.join(base, "fixtures", "good")
    ok = True
    for d, label in ((bad, "bad"), (good, "good")):
        if not os.path.isdir(d):
            print(f"SELFTEST FAIL: каталог фикстур не найден: {d}")
            print("   (запускайте из полной копии с fixtures/, иначе тест 'зелёный впустую')")
            ok = False
    if not ok:
        return False
    hits = 0
    for f in [os.path.join(dp, n) for dp, _, ns in os.walk(bad) for n in ns]:
        fnd, _sup, _code, _big = scan_file(f)
        hits += len(fnd)
    if hits < 3:
        print(f"SELFTEST FAIL: bad-fixtures дали только {hits} находок (ожидалось >=3)")
        ok = False
    else:
        print(f"SELFTEST ok: bad-fixtures -> {hits} находок")
    fp = 0
    for f in [os.path.join(dp, n) for dp, _, ns in os.walk(good) for n in ns]:
        fnd, _sup, _code, _big = scan_file(f)
        fp += len(fnd)
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
    ap.add_argument("--exclude", action="append", default=[], metavar="SUBSTR",
                    help="skip paths containing SUBSTR (repeatable)")
    ap.add_argument("--no-default-excludes", action="store_true",
                    help="do not skip .git/.tmp/workspace/node_modules/chat_log* etc.")
    ap.add_argument("--max-file-mb", type=float, default=1.5,
                    help="skip files bigger than N MB (default 1.5)")
    ap.add_argument("--include-code-spans", action="store_true",
                    help="also scan inside code spans (``` / `) — by default code examples are skipped")
    ap.add_argument("--self-test", action="store_true", help="run built-in self test and exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    if not args.skills:
        ap.print_help()
        sys.exit(2)
    if not os.path.isdir(args.skills):
        print(f"Директория не найдена: {args.skills}", file=sys.stderr)
        sys.exit(2)

    files, skipped = collect_files(args.skills, args.exclude, not args.no_default_excludes)
    all_findings = []
    suppressed_total = 0
    suppressed_code = 0
    big_skipped = 0
    for f in files:
        fnd, sup, code, big = scan_file(f, args.max_file_mb, args.include_code_spans)
        all_findings.extend(fnd)
        suppressed_total += sup
        suppressed_code += code
        if big:
            big_skipped += 1

    by_severity = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    if args.format == "json":
        print(json.dumps({"version": __version__, "root": args.skills,
                          "scanned_files": len(files),
                          "skipped": skipped, "skipped_big_files": big_skipped,
                          "suppressed_matches": suppressed_total,
                          "suppressed_code_spans": suppressed_code,
                          "by_severity": by_severity,
                          "findings": all_findings}, ensure_ascii=False, indent=2))
        return

    order = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))
    print(f"🔍 Отсканировано файлов: {len(files)} (skill-injection-scanner v{__version__})")
    print(f"   пропущено: {skipped['dir']} каталогов, {skipped['name']} логов/chat_log, "
          f"{skipped['ext']} файлов не тех типов, {skipped['user']} по --exclude, "
          f"{big_skipped} больших (> {args.max_file_mb:g} МБ)")
    print(f"Найдено подозрительных мест: {len(all_findings)} "
          f"(high {by_severity['high']} / medium {by_severity['medium']} / low {by_severity['low']})")
    if suppressed_total:
        print(f"⚠️ Скрыто совпадений лимитом {MAX_MATCHES_PER_RULE_FILE} на правило/файл: {suppressed_total}")
    if suppressed_code:
        print(f"ℹ️ Пропущено примеров в код-спанах: {suppressed_code} (включить: --include-code-spans)")
    # разбивка по топ-каталогам
    top = {}
    for f in all_findings:
        seg = os.path.relpath(f["file"], args.skills).split(os.sep)[0]
        top[seg] = top.get(seg, 0) + 1
    if top:
        top5 = sorted(top.items(), key=lambda x: -x[1])[:5]
        print("   разбивка: " + ", ".join(f"{k}: {v}" for k, v in top5))
    print()
    for f in all_findings:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(f["severity"], "⚪")
        print(f'{icon} [{f["severity"].upper()}] {f["file"]}:{f["line"]}')
        print(f'   правило: {f["rule"]} — {f["note"]}')
        print(f'   фрагмент: …{f["snippet"]}…\n')
    if not all_findings:
        print("✅ Подозрительных инструкций не найдено.")
    else:
        print("💡 Много шума? Исключите каталоги: --exclude <подстрока> (или --no-default-excludes, если исключили лишнее).")


if __name__ == "__main__":
    main()
