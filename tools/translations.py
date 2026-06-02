#!/usr/bin/env python3
from pathlib import Path
import re

repo_root = Path(__file__).resolve().parent.parent
in_file = repo_root / "translations.tr"
out_h = repo_root / "translations.h"
out_c = repo_root / "translations.c"

languages = {}
entries = {}


def escape_c_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def c_string(value):
    return '"' + escape_c_string(value) + '"'


def blk_literal(value):
    literal = c_string(value)
    return "{ .data = (uint8_t *)" + literal + ", .size = sizeof(" + literal + ") - 1 }"


def wl(out, line=""):
    out.write(line)
    out.write("\n")


entry_key = str()
entry = str()

lc = -1
for raw_line in in_file.open(encoding="utf-8"):
    line = raw_line.rstrip("\n")
    lc += 1
    if len(line) > 0 and line[0] == "@":
        entry_key = line[1:]
        entry = entry_key
        ok = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", entry_key))
        if ok:
            entries[entry] = []
            continue
        print(
            f"line {lc} ERROR: allowed only alphabetical symbols and underscore, got '{entry_key}'"
        )
        quit(-1)
    elif len(line) > 4 and line[2:4] == ": ":
        lang = line[0:2]
        if not (lang.isalpha() and lang.islower()):
            print(
                f"line {lc} ERROR: expected lowercase language, got '{lang}'",
                lang,
            )
            quit(-1)

        translation = line[4:]
        if languages.get(lang):
            languages[lang] += 1
        else:
            languages[lang] = 1

        entries[entry].append((lang, translation))
    elif line != "":
        print(f"line {lc} ERROR: bad line '{line}'")
        quit(-1)

if not entries:
    print(f"ERROR: no translations found in {in_file}")
    quit(-1)

with out_h.open("w", encoding="utf-8") as out:
    wl(out, "#pragma once")
    wl(out)
    wl(out, '#include "types.h"')
    wl(out)
    wl(out, "typedef enum {")
    for lang in languages:
        wl(out, f"\tlang_{lang},")
    wl(out, "\tlang_COUNT")
    wl(out, "} Lang;")
    wl(out)
    wl(out, "typedef enum {")
    for key in entries:
        wl(out, f"\ttranslation_{key},")
    wl(out, "\ttranslation_COUNT")
    wl(out, "} TranslationKey;")
    wl(out)
    wl(out, "typedef struct {")
    wl(out, "\tblk_t key;")
    wl(out, "\tblk_t value;")
    wl(out, "} TranslationEntry;")
    wl(out)
    wl(out, "extern const TranslationEntry translations[lang_COUNT][translation_COUNT];")
    wl(out)
    wl(out, "Lang lang_from_str(const char *str);")

with out_c.open("w", encoding="utf-8") as out:
    wl(out, '#include "translations.h"')
    wl(out)
    wl(out, "Lang lang_from_str(const char *str)")
    wl(out, "{")
    wl(out, "\tif (!str) {")
    wl(out, "\t\treturn lang_en;")
    wl(out, "\t}")
    for lang in languages:
        wl(out, f"\tif (str[0] == '{lang[0]}' && str[1] == '{lang[1]}') {{")
        wl(out, f"\t\treturn lang_{lang};")
        wl(out, "\t}")
    wl(out, "\treturn lang_en;")
    wl(out, "}")
    wl(out)
    wl(out, "const TranslationEntry translations[lang_COUNT][translation_COUNT] = {")
    for lang in languages:
        wl(out, "\t{")
        for key, values in entries.items():
            found = next((t for t in values if t[0] == lang), None)
            translation = found[1] if found is not None else values[0][1]
            wl(out, "\t\t{")
            wl(out, "\t\t\t.key = " + blk_literal("@" + key + "@") + ",")
            wl(out, "\t\t\t.value = " + blk_literal(translation) + ",")
            wl(out, "\t\t},")
        wl(out, "\t},")
    wl(out, "};")

print(f"wrote {out_h}")
print(f"wrote {out_c}")
