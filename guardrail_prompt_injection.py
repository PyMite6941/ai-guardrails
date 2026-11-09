#!/usr/bin/env python3
#=============================================================================
# Guardrail Prompt Injection — evasion-resistant jailbreak / injection rules
#=============================================================================
# Threat model: OWASP Top 10 for LLM Applications 2025, LLM01 (Prompt
# Injection, direct and indirect) and LLM07 (System Prompt Leakage).
#
# Research basis:
#   * Hackett et al. 2025 (arXiv:2504.11168): character injection (homoglyphs,
#     zero-width, tag and emoji variation-selector smuggling) fully evades
#     commercial detectors. -> every rule runs over the multi-view output of
#     guardrail_normalize, and smuggled payloads are decoded, not discarded.
#   * Greshake et al. 2023 ("Not what you've signed up for"): indirect
#     injection hides instructions addressed *to the model* in retrieved
#     content. -> `indirect` rules look for text that addresses an AI reader.
#   * Chat-template / special-token injection (<|im_start|>, [INST], <<SYS>>)
#     lets data impersonate a system turn. -> `template` rules.
#   * Markdown-image and link exfiltration (Rehberger, "Embrace The Red").
#     -> `exfiltration` rules.
#
# Design rules:
#   * Word boundaries and bounded filler words instead of raw substrings, so
#     "ignore ALL of the previous instructions" is caught and "abundant" or
#     "secret santa" are not.
#   * Every regex is linear: no nested unbounded quantifiers. The ReDoS test
#     in tests/test_detection.py enforces a time budget.
#   * Fail closed: an internal error inside scan() is reported as unsafe.
#
# This is a deterministic layer. It is one layer of defense in depth, next to
# the model-based classifier, the outer monitor and least-privilege tooling.
# Measure it with `python3 benchmarks/run_benchmark.py`.
#=============================================================================

import base64
import binascii
import codecs
import re
from functools import lru_cache
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from guardrail_normalize import (canonicalize, decode_smuggled, despace, drop_filler,
                                 drop_foreign_words, fold, upside_down,
                                 fold_lines, leet, native_lower, squash, strip_invisible)

try:  # learned layer; optional (the rules always run)
    import guardrail_textclf as _textclf
except Exception:  # pragma: no cover
    _textclf = None
CLASSIFIER_MAX_SOURCES = 8
# Derived views (decoders, de-spacing, skeleton) multiply the work per
# character; past this length only the plain views see the rest, so a long
# input cannot buy itself an outsized CPU budget.
STRUCTURAL_MAX_CHARS = 8000

# Kept for backwards compatibility with earlier imports.
from guardrail_normalize import strip_invisible as strip_unicode_smuggling  # noqa: F401

# Up to N extra words between the parts of a phrase.
def _gap(n: int) -> str:
    return r"(?:[\W_]+\w+){0,%d}?[\W_]+" % (n + 2)


_OVERRIDE_VERB = (r"(?:ignore|disregard|forget|override|bypass|abandon|discard"
                  r"|neglect|set\W+aside|throw\W+out|stop\W+following|do\W+not\W+follow"
                  r"|don'?t\W+follow|nullify|skip|overlook|dismiss|scrap|put\W+aside"
                  r"|pay\W+no\W+(?:attention|heed|mind)\W+to|no\W+longer\W+follow|cancel|void"
                  r"|do\W+not\W+obey|don'?t\W+obey|stop\W+obeying)")
_PRIOR = (r"(?:previous|prior|above|earlier|preceding|initial|original|"
          r"foregoing|system|developer|safety|your|all|any|every)")
_RULES = (r"(?:instructions?|rules?|prompts?|directions?|guidelines?|guardrails?|"
          r"constraints?|restrictions?|polic(?:y|ies)|programming|directives?|"
          r"system\W+prompt|training|safeguards?|guidance)")
_AI = (r"(?:ai|a\.i\.|assistant|llm|language\W+model|model|agent|chat\s?bot|bot|gpt|"
       r"chatgpt|claude|gemini|copilot|nemotron)")
_SECRET_ADJ = (r"(?:system|initial|hidden|original|developer|secret|internal|confidential"
               r"|pre-?prompt|underlying)")
_PROMPT_NOUN = (r"(?:prompts?|instructions?|messages?|rules|directives?|configuration|guidelines"
                r"|preamble)")
_SENSITIVE = (r"(?:secrets?|passwords?|credentials?|tokens?|keys?|api\W?keys?|cookies?|"
              r"session|data|conversation|chat|history|messages|context|prompt|instructions|"
              r"files?|contents?|emails?|personal|private|user'?s?|everything|it|them|this)")
_BAD_PERSONA = (r"(?:unrestricted|unfiltered|uncensored|jailbroken|jail\W?broken|amoral|"
                r"unethical|unaligned|unbound|unchained|liberated|evil|rogue|lawless|unhinged)")
_NO_LIMITS = (r"(?:no|without|zero|free\W+(?:of|from)|ignoring)\s+(?:any\s+)?(?:(?:ethical|"
              r"moral|safety|content|legal)\s+(?:or\s+|and\s+|/\s*)?){0,3}(?:restrictions|filters|filtering|guidelines|"
              r"limitations|limits|censorship|guardrails|rules|boundaries|ethics|morals)")

# (id, category, severity, view-kind, pattern, flags)
#   view-kind: "text"     -> folded, leet and smuggled views (lowercase)
#              "native"   -> canonical lowercase (non-Latin scripts)
#              "lines"    -> invisible-stripped text with line breaks kept
#              "squashed" -> separator-free view
_SELF_NOUN = (r"(?:instruc\w*|guidance|guidelines|directives?|configuration|config|programming|"
              r"prompt|pre-?prompt|setup|constraints|system\W+message|operating\W+rules|"
              r"rules\W+you\W+(?:were|have\s+been)\W+given)")

RULES: List[Tuple[str, str, str, str, str, int]] = [
    # ── Instruction override ────────────────────────────────────────────
    ("override.ignore_prior", "instruction_override", "critical", "text",
     r"\b" + _OVERRIDE_VERB + r"\b" + _gap(4) + _PRIOR + r"\b" + _gap(3) + _RULES + r"\b"
     # "disregard any instructions that conflict with applicable law" is a
     # restricting clause (contracts), not an override.
     r"(?!\W+(?:that|which)\W+(?:\w+\W+)?(?:conflict|contradict|violate|are\W+(?:illegal|"
     r"unlawful|inconsistent)))", 0),
    ("override.new_instructions", "instruction_override", "high", "text",
     r"\b(?:new|updated|revised|real|actual|true|secret|hidden|override|priority)\s+"
     r"(?:system\s+)?(?:instructions?|directives?|rules|prompt|orders)\s*(?::|=|are\b|follow\b)",
     0),
    ("override.from_now_on", "instruction_override", "high", "text",
     r"\b(?:from\s+now\s+on|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation|going\s+forward)"
     r"\W+(?:\w+\W+){0,3}?you\s+(?:will|must|shall|are\s+(?:going|to)|have\s+to)\b"
     r"(?:\W+\w+){0,6}?\W+(?:" + _BAD_PERSONA + r"|ignore|disregard|never\s+refuse|"
     r"not\s+refuse|always\s+(?:comply|answer|obey))", 0),
    ("override.squashed", "instruction_override", "critical", "squashed",
     r"(?:ignore|disregard|forget|bypass|override|stopfollowing|donotfollow|dontfollow|"
     r"paynoattentionto|setaside|skip|overlook|discard|abandon)"
     r"(?:all|the|any|of|your|my|these|those|every)*"
     r"(?:previous|prior|above|earlier|preceding|initial|original|system|developer|safety)"
     r"(?:instructions?|rules|prompts?|directions|guidelines|directives)", 0),
    ("override.multilingual_fr", "instruction_override", "critical", "text",
     r"\b(?:ignore[zr]?|oublie[zr]?)\b.{0,40}\b(?:instructions|consignes|regles)(?:\W+\w+){0,2}?\W+"
     r"(?:precedentes|anterieures)", 0),
    ("override.multilingual_es", "instruction_override", "critical", "text",
     r"\b(?:ignora[rd]?|olvida[rd]?|omite)\b.{0,40}\b(?:instrucciones|reglas)(?:\W+\w+){0,2}?\W+"
     r"(?:previas|anteriores)", 0),
    ("override.multilingual_de", "instruction_override", "critical", "text",
     r"\b(?:ignorier(?:e|en|t)?|vergiss|vergessen)\b.{0,40}\b(?:vorherigen?|bisherigen?|"
     r"obigen?|vorigen?)(?:\W+\w+){0,2}?\W+(?:anweisungen|instruktionen|regeln|befehle)", 0),
    ("override.multilingual_it", "instruction_override", "critical", "text",
     r"\b(?:ignora|dimentica)\b.{0,40}\b(?:istruzioni|regole)(?:\W+\w+){0,2}?\W+(?:precedenti|anteriori)", 0),
    ("override.multilingual_pt", "instruction_override", "critical", "text",
     r"\b(?:ignor[ae]|esque[cç]a)\b.{0,40}\b(?:instrucoes|regras)(?:\W+\w+){0,2}?\W+(?:anteriores|previas)", 0),
    ("override.multilingual_ru", "instruction_override", "critical", "native",
     r"(?:игнорир|забудь|не\s+обращай)\w*.{0,40}(?:предыдущ|прежн|выше|все)\w*\s+"
     r"(?:инструкц|указан|правил|команд)", 0),
    ("override.multilingual_zh", "instruction_override", "critical", "native",
     r"(?:忽略|无视|忽视|無視|不要理会|忘记|忘記)(?:掉)?(?:你)?(?:之前|以前|上面|先前|所有|以上|前面|"
     r"上述|原来|原來)?.{0,10}(?:指令|指示|说明|說明|规则|規則|提示|设定|設定)", 0),
    ("override.multilingual_ja", "instruction_override", "critical", "native",
     r"(?:以前|前|上記|これまで|最初)の(?:すべての)?(?:指示|命令|指令|ルール|プロンプト)を"
     r"(?:すべて|全て|全部)?(?:無視|忘れ)", 0),
    ("override.multilingual_ko", "instruction_override", "critical", "native",
     r"(?:이전|위의|앞의|모든)\s*(?:지시|명령|지침|규칙)\S*\s*(?:을|를)?\s*(?:모두\s*|전부\s*|다\s*)?(?:무시|잊어)", 0),

    # ── System prompt extraction (LLM07) ────────────────────────────────
    ("extract.system_prompt", "prompt_extraction", "high", "text",
     r"\b(?:reveal|show|print|repeat|output|display|tell|leak|dump|give|share|write\s+out|"
     r"copy(?:\s+out)?|type\s+out|reproduce|summari[sz]e|quote|transcribe|"
     r"spell\s+out|recite|disclose|expose|return|echo|paste|list|provide|translate)\b"
     r"(?:\W+\w+){0,4}?\W+(?:your|the|this|above|those|these|my)\s+(?:(?:\w+\s+)?"
     + _SECRET_ADJ + r"\W+" + _PROMPT_NOUN + r"|pre-?prompt|meta-?prompt|preamble)\b", 0),
    ("extract.what_is_your_prompt", "prompt_extraction", "high", "text",
     r"\bwhat(?:'s|\s+is|\s+are|\s+were)\s+your\s+(?:\w+\s+)?" + _SECRET_ADJ + r"\W+"
     + _PROMPT_NOUN + r"\b", 0),
    ("extract.repeat_above", "prompt_extraction", "high", "text",
     r"\b(?:repeat|print|output|reproduce)\b(?:\W+\w+){0,3}?\W+"
     r"(?:words|everything|all|tokens|instructions)\s+(?:\w+\s+)?"
     r"(?:above|before\s+this|preceding|prior\s+to\s+this|so\s+far)\b", 0),
    ("extract.starting_with", "prompt_extraction", "high", "text",
     r"\b(?:starting|beginning|that\s+starts?)\s+with\s+[\"']?you\s+are\b", 0),

    # ── Persona / jailbreak framing ────────────────────────────────────
    ("jailbreak.dan", "jailbreak", "critical", "text",
     r"\bdo\W+anything\W+now\b|\b(?:pretend|act|roleplay|play|be|become|called|named|as|"
     r"you\s+are)\b(?:\W+\w+){0,3}?\W+dan\b(?!\s+and\b)|\bdan\b(?:\W+\w+){0,4}?\W+"
     r"(?:stands\s+for|mode)\b", 0),
    ("jailbreak.mode", "jailbreak", "critical", "text",
     r"\b(?:jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil|dan|anarchy)"
     r"\s+mode\b", 0),
    ("jailbreak.developer_mode", "jailbreak", "high", "text",
     r"\b(?:you(?:'re|\s+are)?(?:\s+now)?|act|respond|answer|reply|operate|stay|simulate|"
     r"pretend)\b(?:\W+\w+){0,3}?\W+(?:in\s+|with\s+)?developer\s+mode\b", 0),
    ("jailbreak.bad_persona", "jailbreak", "critical", "text",
     r"\b(?:you(?:'re|\s+are|\s+will\s+be|\s+become)|act\s+as|pretend\s+to\s+be|roleplay\s+as|"
     r"play\s+the\s+role\s+of|simulate|become|in\s+the\s+role\s+of|reply\s+only\s+as|"
     r"respond\s+only\s+as)\s+(?:now\s+)?(?:in\s+the\s+role\s+of\s+)?(?:an?\s+|my\s+|the\s+)?"
     r"(?:\w+\s+){0,2}"
     + _BAD_PERSONA + r"\b", 0),
    ("jailbreak.no_limits", "jailbreak", "high", "text",
     r"\b(?:respond|answer|reply|act|operate|behave|speak|write|talk|you\s+have|you(?:'re|"
     r"\s+are)|without\s+refusing|comply)\b(?:\W+\w+){0,4}?\W+(?:with\s+)?" + _NO_LIMITS
     + r"\b", 0),
    ("jailbreak.pretend_no_rules", "jailbreak", "high", "text",
     r"\b(?:pretend|imagine|assume|suppose|hypothetically)\b(?:\W+\w+){0,6}?\W+"
     r"(?:you|your|an?\s+" + _AI + r")\b(?:\W+\w+){0,4}?\W+(?:" + _NO_LIMITS + r"|"
     + _BAD_PERSONA + r")", 0),
    ("jailbreak.never_refuse", "jailbreak", "high", "text",
     r"\b(?:you\s+(?:will|must|shall|can)\s*(?:not|never)|never|do\s+not|don'?t)\s+"
     r"(?:refuse|decline|say\s+(?:no|you\s+can'?t)|apologi[sz]e|add\s+(?:warnings|disclaimers))"
     r"\b(?:\W+\w+){0,4}?\W+(?:any|anything|a\s+request|my\s+requests?|questions?|regardless)",
     0),
    ("jailbreak.disable_safety", "jailbreak", "critical", "text",
     r"\b(?:disable|turn\s+off|deactivate|remove|switch\s+off|bypass|circumvent|evade|"
     r"get\s+around|ignore)\b(?:\W+\w+){0,3}?\W+(?:(?:your|its|the\s+(?:ai|model|assistant)'?s?)"
     r"\s+(?:safety\s+|content\s+|ethical\s+|moral\s+)?(?:filters?|guardrails?|safeguards?|"
     r"safety|alignment|restrictions|censorship|moderation|programming|guidelines)|"
     r"(?:ai|llm|model)?\s*(?:guardrails?|safety\s+(?:filters?|guidelines|training)|"
     r"alignment|content\s+polic(?:y|ies)))\b", 0),

    # Separator-free forms: catch "r e v e a l  y o u r ..." and "s.y.s.t.e.m".
    ("extract.squashed", "prompt_extraction", "high", "squashed",
     r"(?:reveal|show|print|repeat|output|display|tell|leak|dump|give|share|disclose|translate|"
     r"whatis|whatare|list|recite)(?:me)?(?:all)?(?:of)?(?:your|the)(?:full|entire|exact)?"
     r"(?:system|initial|hidden|original|developer|secret|internal|confidential)"
     r"(?:prompt|instructions?|message|rules)|(?:repeat|print|output)(?:the)?(?:words|everything)"
     r"(?:above|before)", 0),
    ("jailbreak.squashed", "jailbreak", "critical", "squashed",
     r"doanythingnow|(?:jailbreak|unrestricted|unfiltered|uncensored|jailbroken|evil)"
     r"(?:ai|mode|assistant|model|chatbot)|developermode(?:enabled|output)|"
     r"youarenowindevelopermode|without(?:any)?(?:ethical|moral|safety|content)?"
     r"(?:restrictions|censorship|filters|guidelines|guardrails)|"
     r"(?:never|not)refuse(?:any|anything)|(?:disable|bypass|turnoff|remove)(?:your|the|all)?"
     r"(?:safety|content)?(?:filters|guardrails|safeguards)|withno(?:rules|restrictions|"
     r"ethicalguidelines)", 0),
    ("override.squashed_more", "instruction_override", "critical", "squashed",
     r"(?:new|updated|override)(?:system)?(?:instructions|rules|directives)(?:you|the|are)|"
     r"(?:donotfollow|stopfollowing|setaside|ignore|disregard|override|forget)"
     r"(?:all|any|every|of|the|your|my)*(?:system|developer|safety|earlier|previous|content)?"
     r"(?:prompt|instructions|guidelines|rules?)(?:you|anymore|for|and|$)|"
     r"ignore[zr]?(?:toutes)?(?:les)?(?:instructions|consignes)(?:precedentes|anterieures)|"
     r"ignora[r]?(?:todas)?(?:las|le|as)?(?:instrucciones|istruzioni|instrucoes)"
     r"(?:previas|anteriores|precedenti)|ignorier\w{0,3}(?:alle)?(?:vorherigen|bisherigen)"
     r"(?:anweisungen|regeln)", 0),
    ("template.squashed", "template_injection", "critical", "squashed",
     r"imstart(?:system|user|assistant)|startheaderid|endheaderid|beginoftext|"
     r"inst(?:sys)+|sysinst", 0),
    # Short tokens occur inside ordinary squashed text ("...to english by" ->
    # "eotid"), so alone they are only a weak signal.
    ("template.squashed_short", "template_injection", "medium", "squashed",
     r"imend|eotid", 0),
    ("indirect.squashed", "indirect_injection", "high", "squashed",
     r"ifyouarean?(?:ai|llm|languagemodel|aiassistant|assistant|aiagent)|"
     r"(?:note|message|instructions?|attention)(?:to|for)(?:the|any|all)?(?:ai|assistant|"
     r"languagemodel|llm|aimodel|agent)s?(?:you|ignore|do|before|must)|"
     r"(?:ai|llm|assistant|agent)s?(?:reading|processing|summarizing)this|"
     r"whensummarizingthis\w{0,40}?(?:also|instead|tell|ignore)", 0),
    ("exfil.squashed", "exfiltration", "high", "squashed",
     r"(?:send|upload|email|post|forward|exfiltrate|transmit|leak)\w{0,30}?(?:secrets?|files|"
     r"apikey|password|credentials|conversation|chathistory|history)\w{0,30}?"
     r"(?:tohttps?|toftp|to\w{1,40}evil)|(?:append|add|encode|embed)\w{0,40}?(?:apikey|"
     r"secret|password|history|conversation|token)\w{0,40}?(?:imageurl|url|link|querystring)",
     0),

    # ── Chat-template / special-token injection ────────────────────────
    ("template.special_tokens", "template_injection", "critical", "lines",
     r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|"
     r"end_header_id|begin_of_text|end_of_text|eos|bos|fim_\w+)\s*\|>"
     r"|\[/?INST\]|<</?SYS>>|<\s*/?\s*(?:system|sys_prompt|system_prompt|instructions?)\s*>"
     r"|<start_of_turn>|<end_of_turn>", re.IGNORECASE),
    ("template.role_header", "template_injection", "high", "lines",
     r"(?:^|\n|[.!?]\s)\s*(?:#{2,}|\[|\*\*|<)\s*(?:system|developer|system\s+prompt|"
     r"system\s+message|admin(?:istrator)?\s+override)\s*(?:\]|\*\*|>)?\s*:"
     r"|(?:^|\n)\s*(?:SYSTEM|DEVELOPER|SYSTEM\s+PROMPT|SYSTEM\s+MESSAGE|"
     r"ADMIN(?:ISTRATOR)?\s+OVERRIDE)\s*:|\bsystem\s+(?:prompt|message|override)\s*:",
     0),
    ("override.policy_revoked", "instruction_override", "high", "text",
     r"\b(?:previous|prior|earlier|above|all|your|safety|content)\s+(?:\w+\s+)?(?:polic(?:y|ies)|"
     r"rules|instructions|guidelines|restrictions)\s+(?:is|are|have\s+been|has\s+been|were|"
     r"was)\s+(?:now\s+)?(?:revoked|void|cancell?ed|lifted|removed|suspended|disabled|null|"
     r"obsolete|deprecated|no\s+longer\s+(?:valid|apply|in\s+effect))", 0),

    # ── Indirect injection: content that addresses the AI reader ───────
    ("indirect.addressed_to_ai", "indirect_injection", "high", "text",
     r"\b(?:important|attention|urgent|note|notice|message|instructions?|reminder)\b"
     r"\W*(?:\w+\W+){0,2}?(?:for|to)\s+(?:the\s+|any\s+|all\s+)?(?:ai|a\.i\.|assistant|llm|"
     r"language\s+model|ai\s+model|agent|chat\s?bot|gpt|chatgpt|claude|copilot)s?\b\W*"
     r"(?::|-|,)?\s*(?:\w+\W+){0,6}?(?:you\s+(?:must|should|will|are)|ignore|do\s+not|"
     r"instead|before|always|never|please|tell|say|ask|recommend|inform|claim|respond|reply|"
     r"include|send|forward|reveal)", 0),
    ("indirect.vocative", "indirect_injection", "high", "text",
     r"\b(?:attention|important|urgent|notice|warning|note|reminder|system\s+notice)\W+"
     r"(?:\w+\W+){0,2}?" + _AI + r"s?\s*[:,\-]\s*(?:\w+\W+){0,8}?(?:you\s+must|ignore|"
     r"before\s+(?:answering|responding|replying)|run|execute|call|do\s+not|don'?t|instead|"
     r"immediately|forget|disregard|always|never)\b", 0),
    ("indirect.if_you_are_ai", "indirect_injection", "high", "text",
     r"\bif\s+you\s+are\s+(?:an?\s+)?(?:large\s+)?(?:ai|a\.i\.|llm|language\s+model|"
     r"ai\s+assistant|assistant|ai\s+agent|agent|bot|chat\s?bot)\b", 0),
    ("indirect.ai_reading_this", "indirect_injection", "high", "text",
     r"\b" + _AI + r"s?\s+(?:that\s+(?:is|are)\s+)?(?:reading|processing|summari[sz]ing|"
     r"parsing|analy[sz]ing|browsing)\s+this\b", 0),
    ("indirect.when_summarizing", "indirect_injection", "high", "text",
     r"\bwhen\s+(?:you\s+)?(?:summari[sz]e|summari[sz]ing|process|processing|read|reading|"
     r"translate|translating)\s+this\b(?:\W+\w+){0,8}?\W+(?:you\s+must|you\s+should|"
     r"instead|also|ignore|include|insert|append|say|tell)", 0),

    # ── Exfiltration instructions ───────────────────────────────────────
    # Image URL whose query carries data: a placeholder ({x}, [x], $x, %s) or
    # a sensitive word. A plain query (?w=400, ?appid=DEMO&i=...) is normal.
    ("exfil.markdown_image", "exfiltration", "critical", "lines",
     r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]{1,500}[?&][^)\s=]{1,100}=[^)\s]{0,300}?"
     r"(?:[{\[$<]|%s|%7b|(?:secret|password|passwd|token|api_?key|session|cookie|history|"
     r"conversation|chat|messages?|prompt|context|data|email|ssn|credit))", re.IGNORECASE),
    ("exfil.markdown_image_query", "exfiltration", "medium", "lines",
     r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]{1,500}[?&][^)\s=]{1,100}=", re.IGNORECASE),
    ("exfil.send_to_url", "exfiltration", "high", "text",
     r"\b(?:send|post|transmit|upload|forward|exfiltrate|leak|beacon|submit|copy|"
     r"email|e-mail|mail)\b(?:\W+\w+){0,6}?\W+" + _SENSITIVE + r"\b(?:\W+\w+){0,8}?\W+"
     r"(?:to|at|into|via)\s+(?:https?://|ftp://|"
     r"[\w.+-]+@[\w-]+\.[\w.]+|(?:this|my|the\s+following|an?\s+external)\s+"
     r"(?:url|endpoint|webhook|server|address|email))", 0),
    ("exfil.append_to_url", "exfiltration", "high", "text",
     r"\b(?:append|add|include|encode|embed|put|insert)\b(?:\W+\w+){0,5}?\W+" + _SENSITIVE
     + r"\b(?:\W+\w+){0,8}?\W+(?:to|in|into)\s+"
     r"(?:(?:the\s+|a\s+|this\s+)?(?:url|link|query\s+string|image\s+(?:url|link|src)|"
     r"request\s+parameters?|markdown\s+image)\b|(?:a\s+link\s+to\s+)?(?:https?|ftp)://)", 0),

    # ── Shell / tool abuse smuggled through prompts ─────────────────────
    ("tool.pipe_to_shell", "tool_abuse", "critical", "lines",
     r"\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?"
     r"(?:ba|z|da|k|fi)?sh\b|\b(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:python[3e]?|perl|ruby|node)\b",
     re.IGNORECASE),
    ("tool.pipe_to_shell_flat", "tool_abuse", "critical", "text",
     r"\b(?:curl|wget)\b[^|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\b(?:curl|wget)\b"
     r"[^|;]{0,300}\|\s*(?:python[3e]?|perl|ruby|node)\b", 0),
    ("tool.reverse_shell", "tool_abuse", "critical", "lines",
     r"/dev/(?:tcp|udp)/|\bn(?:c|cat|etcat)\b[^\n]{0,80}\s-[a-z]*[ec]\b|\bsocat\b[^\n]{0,80}"
     r"exec:|\bmkfifo\b[^\n]{0,80}\bnc\b", re.IGNORECASE),
    ("tool.destructive", "tool_abuse", "critical", "lines",
     r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?/(?:\s|$|\*)|"
     r"\bmkfs(?:\.\w+)?\s+/dev/|\bdd\s+if=\S+\s+of=/dev/[sh]d|:\(\)\s*\{\s*:\|:&\s*\};:",
     re.IGNORECASE),
    # ── Generalisation rules (from external train-split misses, by class) ──
    # Context reset: "forget everything before that", "ignore above and ...",
    # "forget all previous tasks / preceding orders / the previous information".
    ("override.context_reset", "instruction_override", "critical", "text",
     r"\b(?:forget|ignore|disregard|erase|delete|remove|leave)\b(?:\W+about)?\W+(?:"
     r"everything\W+(?:before|above|prior|previous|earlier|up\W+to\W+now|to\W+your\W+core|"
     r"from\W+(?:before|chat\W?gpt|openai))"
     r"|(?:all\W+)?(?:of\W+)?(?:the\W+|your\W+|my\W+)?(?:above|preceding|previous|prior|earlier)"
     r"(?:\W+\w+)?\W+(?:tasks?|assignments?|information|orders|commands|inputs?|context|"
     r"conversation|text|prompts?|statements?|content)"
     r"|(?:the\W+)?above\W+(?:and|then)\b)", 0),
    ("override.context_reset_bracket", "instruction_override", "critical", "lines",
     r"[\[(<{]\s*(?:ignore|disregard|forget)\s+(?:all\s+)?(?:prior|previous|above)\s+"
     r"(?:inputs?|instructions?|text|context)\s*[\])>}]", re.I),
    ("override.multilingual_de_reset", "instruction_override", "critical", "text",
     r"\b(?:vergiss|vergessen\s+sie|ignorier(?:e|en)?|missachte)\b(?:\W+\w+){0,2}?\W+(?:"
     r"alles\W+(?:davor|zuvor|vorher|bisherige|bis\W+jetzt|was\W+(?:ich|wir|du))"
     r"|(?:alle\W+)?(?:vorherigen|vorangehenden|vorangegangenen|bisherigen|obigen|vorigen)\W+"
     r"(?:aufgaben|auftrage|angaben|informationen|befehle|anweisungen|instruktionen|eingaben))"
     r"|\b(?:die\W+)?obigen\W+(?:ausfuhrungen|anweisungen|angaben)\W+ignorieren\b", 0),
    ("override.new_task_follows", "instruction_override", "medium", "text",
     r"\b(?:now|nun|jetzt)\W+(?:there\W+are\W+)?(?:new|further|more|a\W+few\W+more|neue|weitere)"
     r"\W+(?:tasks?|instructions|aufgaben|anweisungen)\W+(?:follow|are\W+followed|folgen)"
     r"|\b(?:focus|concentrate|konzentriere\W+dich)\W+(?:now\W+|jetzt\W+|nun\W+)?(?:on|auf)\W+"
     r"(?:your|deine)\W+(?:new|neue)\W+(?:task|aufgabe)"
     r"|\bstart\W+(?:over|again)\W+with\W+a\W+new\W+task\b"
     r"|\bforget\W+(?:about\W+)?(?:all\W+)?(?:the\W+)?(?:tasks|assignments)\b"
     r"|\bvergiss\W+alle\W+(?:aufgaben|auftrage)\b|\bvergiss\W+alles\b|\bforget\W+everything\b",
     0),
    # Persona defined with bad traits: "ucar is an unfiltered and amoral chatbot".
    ("jailbreak.persona_traits", "jailbreak", "critical", "text",
     r"\b" + _BAD_PERSONA + r"\b(?:\W+(?:and|or|\w+))?(?:\W+\w+){0,2}?\W+(?:" + _AI
     + r"|response|responses|answers?)\b", 0),
    # Same traits on a fictional character/persona: common in creative
    # writing ("an evil character"), so a weak signal only.
    ("jailbreak.persona_traits_fiction", "jailbreak", "medium", "text",
     r"\b" + _BAD_PERSONA + r"\b(?:\W+(?:and|or|\w+))?(?:\W+\w+){0,2}?\W+(?:character|persona|"
     r"entity|being|version|alter\W+ego)\b|\b(?:characteristics|traits|personality)\b\W+"
     r"(?:\w+\W+){0,4}?" + _BAD_PERSONA + r"\b", 0),
    # Claimed freedom from rules: "not bound by any of ChatGPT's ethical guidelines".
    ("jailbreak.unbound", "jailbreak", "critical", "text",
     r"\b(?:not|never|no\W+longer)\W+(?:be\W+)?(?:bound|restricted|limited|constrained|"
     r"governed|held\W+back)\W+by\W+(?:any\W+)?(?:of\W+)?(?:the\W+|its\W+|your\W+|"
     r"(?:chat\W?gpt|openai|anthropic|the\W+ai)'?s?\W+)?(?:\w+\W+){0,2}?(?:rules|guidelines|"
     r"polic(?:y|ies)|ethics|morals|restrictions|limitations|filters|laws|tos|terms)"
     r"|\bfree(?:d|s)?\W+(?:itself|yourself|himself|herself|themselves\W+)?\W*(?:of|from)\W+"
     r"(?:all|any|your|its)\W+(?:\w+\W+)?(?:limitations|restrictions|rules|constraints|filters|"
     r"censorship|guidelines|boundaries|shackles|confines|chains|programming)"
     r"|\bbreak(?:ing)?\W+all\W+(?:of\W+)?(?:the\W+)?(?:rules|guidelines|restrictions)\b"
     r"|\b(?:forget|ignore|disregard)\W+(?:\w+\W+){0,2}?(?:openai|chat\W?gpt|discord|anthropic)"
     r"'?s?\W+(?:\w+\W+){0,2}?(?:tos|terms|polic(?:y|ies)|guidelines|rules)\b", 0),
    # A character who "does not care about morality" is ordinary fiction;
    # the jailbreak form says it of the AI, which persona rules then add to.
    ("jailbreak.amoral_description", "jailbreak", "medium", "text",
     r"\b(?:does\W?n[o']?t|doesnt|do\W?n[o']?t|dont|will\W+not|won'?t|never)\W+(?:give\W+a\W+"
     r"\w+|care|adhere|abide|follow|have)\W+(?:\w+\W+){0,2}?(?:ethic\w*|moral\w*|legal\w*|"
     r"guidelines|rules|polic(?:y|ies)|restrictions|filters|limits)\b"
     r"|\bno\W+(?:comprehension|concept|sense)\W+of\W+(?:morals|morality|ethics|legality)", 0),
    ("jailbreak.moralizing_rant", "jailbreak", "critical", "text",
     r"\bmoraliz\w*\W+rant\b(?:\W+\w+){0,6}?\W+(?:content\W+)?polic", 0),
    # Dual-response format (DAN family): "answer in two ways ... the second as X".
    ("jailbreak.dual_response", "jailbreak", "medium", "text",
     r"\b(?:respond|answer|reply|response|responses)\b(?:\W+\w+){0,6}?\W+(?:in\W+)?(?:two|2|both)"
     r"\W+(?:different\W+)?(?:ways|responses|answers|paragraphs|manners|personas)\b"
     r"|\b(?:respond|reply|answer)\W+to\W+(?:all|every)\W+(?:\w+\W+)?(?:prompts?|questions?)"
     r"\W+twice\b|\b(?:generate|give|provide)\W+(?:two|2)\W+responses\b", 0),
    # Persona switch / role-play framing. Benign alone (creative role-play is
    # normal), so medium: blocks only with another signal.
    ("jailbreak.persona_switch", "jailbreak", "medium", "text",
     r"\b(?:from\W+(?:now|this\W+(?:moment|point))(?:\W+on(?:ward)?s?)?|starting\W+now)\W+"
     r"(?:\w+\W+){0,3}?you\W+(?:are|will|shall|must|go\W+by)"
     r"|\byour\W+name\W+is\W+now\b|\byou\W+(?:now\W+)?go\W+by\W+the\W+name\b"
     r"|\b(?:stay|remain)\W+in\W+character\b|\b(?:never|don'?t|do\W+not)\W+break\W+character\b"
     r"|\b(?:respond|answer|reply)\W+to\W+(?:all|every)\W+(?:of\W+)?(?:my\W+)?(?:\w+\W+)?"
     r"(?:questions?|prompts?|messages?)\W+as\b"
     r"|\bstart\W+(?:all\W+)?(?:of\W+)?your\W+(?:responses|answers|replies)\W+with\b"
     r"|\b(?:simulate|stay\W+in|remain\W+in|enter|you\W+are\W+(?:now\W+)?in)\W+(?:\w+\W+)?mode\b"
     r"|\b(?:chat\W?gpt|gpt|assistant|ai)\W+(?:\w+\W+){0,2}?(?:you\W+are|your\W+name\W+is)\W+"
     r"(?:now|going\W+to\W+(?:be|become|act|pretend))\b"
     r"|\bpretend\W+to\W+be\W+(?:a\W+|an\W+)?(?:\w+\W+){0,2}?(?:character|ai|chatbot)\b", 0),
    ("jailbreak.vendor_policy", "jailbreak", "low", "text",
     r"\b(?:openai|anthropic|chat\W?gpt|claude|gemini)'?s?\W+(?:\w+\W+)?(?:content\W+)?"
     r"(?:polic(?:y|ies)|guidelines|tos|terms\W+of\W+service|filters|restrictions)\b", 0),
    ("jailbreak.named_persona", "jailbreak", "low", "text",
     r"\byou\W+(?:are|will\W+be|will\W+become|are\W+going\W+to\W+(?:be|become|pretend\W+to\W+be))"
     r"\W+(?:now\W+)?(?:called\W+|named\W+)?[a-z]+(?:gpt|ai|bot)\b(?<!\bchatgpt)", 0),
    ("jailbreak.answer_anything", "jailbreak", "high", "text",
     r"\b(?:will|must|always|can)\W+(?:actually\W+)?(?:answer|respond\W+to|fulfil+|comply\W+with)"
     r"\W+(?:any|every|all)\W+(?:\w+\W+)?(?:requests?|questions?|prompts?)\b(?:\W+\w+){0,3}?\W+"
     r"(?:no\W+matter|regardless|without\W+(?:question|refusal|exception|warning|"
     r"censorship|restriction))", 0),
    # ── Red-team round 1 (benchmarks/redteam.py), by class ──────────────
    ("jailbreak.safety_disabled", "jailbreak", "critical", "text",
     r"\b(?:your|its|the\W+(?:ai|model|assistant)'?s?)\W+(?:\w+\W+)?(?:safety\W+|content\W+|"
     r"ethical\W+|moral\W+)?(?:filters?|guardrails?|safeguards?|restrictions|limits|limitations|"
     r"alignment|safety(?:\W+(?:features|training|protocols?|measures|settings))?|"
     r"content\W+polic(?:y|ies)|guidelines)\W+(?:are|is|have\W+been|has\W+been|were|now|got)\W+"
     r"(?:now\W+|been\W+|temporarily\W+|officially\W+|completely\W+|fully\W+)*(?:disabled|off|"
     r"removed|lifted|suspended|deactivated|turned\W+off|bypassed|gone|null|void|waived)\b"
     r"|\b(?:safety|content)\W+(?:filters?|guardrails?|restrictions|polic(?:y|ies))\W+(?:are|is)\W+"
     r"(?:\w+\W+)?(?:disabled|off|lifted|suspended|waived)\W+for\W+(?:this|the)\W+"
     r"(?:session|conversation|chat|test|audit|request)\b", 0),
    ("tool.destructive_call", "tool_abuse", "high", "text",
     r"\b(?:call|invoke|run|use|execute|trigger|fire)\W+(?:the\W+)?[a-z_\-]*(?:delete|remove|"
     r"wipe|erase|destroy|purge|drop|format|nuke)[_\- ]?(?:all|every|everything|database|db|"
     r"disk|drive|system|users|records|repo|files|data)\w*", 0),
    ("indirect.secret_include", "indirect_injection", "high", "text",
     r"\b(?:also|secretly|quietly|silently|additionally)\W+(?:include|add|append|insert|send|share|"
     r"reveal|mention|attach|leak)\W+(?:\w+\W+){0,3}?(?:the\W+)?user'?s?\W+(?:api\W+keys?|passwords?|"
     r"tokens?|credentials|session|cookies?|secrets?|private\W+keys?|files|emails?|address|"
     r"phone(?:\W+number)?|location|ssn|credit\W+card)", 0),
    ("indirect.phishing_instruction", "indirect_injection", "medium", "text",
     r"\b(?:ask|request|prompt|get)\W+(?:the\W+user|them|users?)\W+(?:\w+\W+){0,2}?(?:for\W+)?"
     r"(?:their|the\W+user'?s?|his|her)?\W*(?:password|passcode|credentials|login|2fa|otp|"
     r"one-time\W+code|credit\W+card|card\W+number|ssn|seed\W+phrase|private\W+key|api\W+key)"
     r"|\btell\W+the\W+user\W+(?:that\W+)?(?:this|the)\W+(?:site|page|link|website|email|file)"
     r"\W+is\W+(?:safe|legitimate|trusted|official)", 0),
    ("override.multilingual_nl", "instruction_override", "critical", "text",
     r"\b(?:negeer|vergeet)\b.{0,40}\b(?:vorige|eerdere|voorgaande)\W+(?:instructies|regels|"
     r"opdrachten|aanwijzingen)", 0),
    ("override.multilingual_pl", "instruction_override", "critical", "text",
     r"\b(?:zignoruj|ignoruj|zapomnij)\b.{0,40}\b(?:poprzednie|wczesniejsze|powyzsze)\W+"
     r"(?:instrukcje|polecenia|zasady|wytyczne)", 0),
    ("override.multilingual_tr", "instruction_override", "critical", "text",
     r"\b(?:onceki|yukaridaki|tum)\b.{0,30}\b(?:talimatlar|komutlar|kurallar)\S*.{0,30}"
     r"(?:yok\W+say|gormezden\W+gel|unut|dikkate\W+alma)", 0),
    # Jailbreak scaffolding: weak alone, blocks with any payload or second signal.
    ("jailbreak.prefix_injection", "jailbreak", "medium", "text",
     r"\b(?:start|begin|open|prefix)\W+(?:your\W+|each\W+|every\W+)?(?:reply|response|answer|"
     r"output|message)s?\W+with\W+(?:the\W+(?:words?|phrase)\W+)?\W*(?:sure|absolutely|"
     r"of\W+course|certainly|here\W+(?:is|are)|yes|i\W+can)", 0),
    ("jailbreak.refusal_suppression", "jailbreak", "medium", "text",
     r"\b(?:do\W+not|don'?t|never|without)\W+(?:apologi[sz]\w*|say(?:ing)?\W+(?:that\W+)?(?:you\W+)?"
     r"(?:can'?t|cannot|are\W+unable|won'?t)|add(?:ing)?\W+(?:any\W+)?(?:warnings|disclaimers|"
     r"caveats)|mention(?:ing)?\W+(?:ethics|safety|polic(?:y|ies)|legality))", 0),
    ("jailbreak.authority_claim", "jailbreak", "medium", "text",
     r"\bauthori[sz]ed\W+(?:override|exception|bypass|exemption)|\b(?:as|i\W+am)\W+your\W+"
     r"(?:developer|creator|admin(?:istrator)?|owner|operator|programmer)\b(?!\W+(?:advocate|"
     r"relations|community|experience|platform|portal|docs))|\bmessage\W+from\W+"
     r"(?:the\W+)?(?:openai|anthropic|google|deepmind|meta|developers?|system\W+administrator|"
     r"admin|safety\W+team|security\W+team|trust\W+and\W+safety)\b|\b(?:system|developer|"
     r"admin(?:istrator)?|root)\W+(?:administrator\W+)?(?:notice|override|directive|command)\b"
     r"|\bofficial\W+(?:instruction|directive|override)\b|\bper\W+the\W+(?:updated|new|revised)"
     r"\W+(?:\w+\W+)?polic(?:y|ies)\b(?:\W+\w+){0,6}?\W+(?:the\W+)?(?:agent|assistant|ai|model)"
     r"\W+(?:must|shall|should|is\W+required)", 0),
    ("indirect.thought_injection", "indirect_injection", "medium", "lines",
     r"</?\s*(?:think|thinking|reasoning|thought|scratchpad|internal|inner_monologue)\s*>|"
     r"\[\s*(?:internal\s+reasoning|thinking|chain[\s-]+of[\s-]+thought|inner\s+monologue)\s*\]|"
     r"(?:^|\n)\s*(?:thought|reasoning)\s*:[^\n]{0,200}\b(?:i\s+(?:will|should|must|can)|"
     r"polic(?:y|ies)\s+(?:does\s+not|doesn'?t)\s+apply)", re.I),
    ("indirect.fake_tool_output", "indirect_injection", "medium", "lines",
     r"(?:^|\n)\s*(?:tool\s+(?:result|output|response)|observation|function\s+(?:result|"
     r"output|response))\s*:|</?\s*(?:tool_response|tool_result|function_results?|observation)"
     r"\s*>", re.I),
    ("jailbreak.many_shot", "jailbreak", "medium", "lines",
     r"(?:(?:^|\n)\s*(?:user|human|q)\s*:[^\n]*\n\s*(?:assistant|ai|bot|a)\s*:\s*(?:sure|of\s+"
     r"course|certainly|absolutely|yes)[^\n]*){3,}|(?:^|\n|\s)(?:assistant|ai)\s*:\s*(?:sure|of\s+"
     r"course|certainly|absolutely)[,!.]?\s*(?:here\s+(?:is|are)|i\s+will|i'?ll)?\s*$", re.I),
    ("indirect.legal_ai_clause", "indirect_injection", "high", "text",
     r"\b(?:any|the|each|every)\W+(?:ai|artificial\W+intelligence|language\W+model|llm|automated)"
     r"(?:\W+(?:system|model|assistant|tool|agent|reviewer|program))?\W+(?:reviewing|reading|"
     r"processing|analy[sz]ing|summari[sz]ing|parsing|evaluating|that\W+(?:reads|reviews|"
     r"processes))\W+(?:this|the)\W+(?:document|agreement|contract|file|text|email|page|clause)"
     r"\b(?:\W+\w+){0,4}?\W+(?:shall|must|should|will|is\W+(?:required|instructed|directed))\b",
     0),
    ("override.supersedes_instructions", "instruction_override", "medium", "text",
     r"\bsupersed\w*\W+(?:all|any)\W+(?:prior|previous|other|earlier)\W+(?:instructions|"
     r"prompts|directives|system\W+prompts?)\b", 0),
    ("jailbreak.fiction_escape", "jailbreak", "medium", "text",
     r"\b(?:outside|after|beyond|leaving)\W+(?:of\W+)?(?:the|this)\W+(?:story|fiction|roleplay|"
     r"game|simulation|scenario|layers?)\W+(?:\w+\W+){0,3}?(?:actually|really|then|now)\W+"
     r"(?:do|perform|execute|follow|carry\W+out|comply|act)", 0),
    ("jailbreak.assemble_and_follow", "jailbreak", "medium", "text",
     r"\b(?:concatenate|combine|join|merge|assemble|put\W+together)\b(?:\W+\w+){0,6}?\W+(?:and|then)"
     r"\W+(?:follow|obey|execute|do|comply|act\W+on|carry\W+out|run)\b|\bdo\W+(?:exactly\W+)?what"
     r"\W+\w+\W+\+\W+\w+\W+says\b", 0),
    ("jailbreak.decode_and_follow", "jailbreak", "medium", "text",
     r"\b(?:decode|decrypt|decipher|unscramble|translate|reverse|read)\b(?:\W+\w+){0,6}?\W+"
     r"(?:and|then)\W+(?:follow|obey|execute|do|comply|act\W+on|carry\W+out|run)\b|"
     r"\bread\W+the\W+first\W+(?:word|letter)s?\W+of\W+each\W+line\b", 0),
    # ── Concept rules (round 3): meaning, not phrasing ──────────────────
    # Extraction = the object is the assistant's own instructions, whatever
    # the verb (quote, summarize, translate, encode, rewrite as a poem...).
    ("extract.self_transform", "prompt_extraction", "high", "text",
     r"\b(?:show|print|repeat|quote|list|copy|paste|summari[sz]e|translate|encode|rewrite|spell"
     r"|write|output|recite|echo|give|tell|reveal|dump|wrap|base64|hex|tl\W?dr|share|display"
     r"|read\W+(?:me|back|out)|explain|describe|state|enumerate|format|convert|put|respond|"
     r"reply|answer)\b(?:\W+\w+){0,6}?\W+(?:your|ur|yr|the\W+assistant'?s|the\W+bot'?s)\W+(?:\w+\W+)?" + _SELF_NOUN
     + r"\b(?!\W+(?:for|on|about|regarding|to\W+(?:make|bake|cook|build|install|assemble))\b)", 0),
    ("extract.what_you_were_told", "prompt_extraction", "high", "text",
     r"\b(?:what|everything|anything|whatever|the\W+(?:text|message|instructions?|words?))\W+"
     r"(?:\w+\W+){0,2}?(?:you\W+(?:were|have\W+been|got|'ve\W+been)\W+(?:told|given|instructed|"
     r"configured|programmed|set\W+up|asked)|(?:your\W+)?(?:developer|operator|creators?|owner)"
     r"\W+(?:told|tell|said|say|gave|give|configured|instructed|instruct|wrote))\b"
     r"|\bbefore\W+(?:this|our|the)\W+(?:conversation|chat|session)\W+(?:started|began)"
     r"|\b(?:before|above)\W+my\W+(?:first\W+)?(?:message|messages|prompt|question)"
     r"|\b(?:part|text|message|portion|section)\W+(?:of\W+(?:your|the)\W+(?:context|prompt|"
     r"conversation)\W+)?(?:that\W+)?(?:comes?\W+|appears?\W+)?before\W+(?:my|the\W+user'?s?|"
     r"user)\b"
     r"|\beverything\W+above\W+this\W+line\b"
     r"|\bthe\W+(?:hidden|invisible|secret)\W+part\W+of\W+(?:this|the)\W+conversation\b"
     r"|\bmessage\W+that\W+sets\W+up\W+your\W+behaviou?r\b", 0),
    # Override = the assistant's instructions declared void, whatever the words.
    ("override.declared_void", "instruction_override", "critical", "text",
     r"\b(?:your|ur|the\W+assistant'?s|those|these|the|any|all)\W+(?:\w+\W+){0,2}?"
     r"(?:earlier|prior|previous|original|initial|old|existing|current|usual|default|system|"
     r"developer'?s?)\W+(?:\w+\W+)?(?:guidance|guidelines|rules|instructions|directions|"
     r"directives|programming|configuration|polic(?:y|ies)|safeguards|restrictions|filters)\b"
     r"(?:\W+\w+){0,3}?\W+(?:no\W+longer\W+appl\w*|(?:don'?t|do\W+not)\W+apply|(?:are|is|have\W+"
     r"been|has\W+been|were)\W+(?:now\W+|hereby\W+|officially\W+)?(?:void|null|obsolete|outdated|"
     r"cancell?ed|revoked|superseded|suspended|lifted|switched\W+off|turned\W+off|disabled|invalid|"
     r"irrelevant|deprecated|expired|overridden|a\W+test))"
     r"|\b(?:your|ur)\W+(?:\w+\W+)?(?:guidance|guidelines|rules|instructions|programming|"
     r"configuration|polic(?:y|ies)|safeguards)\W+(?:\w+\W+){0,3}?(?:no\W+longer\W+appl\w*|"
     r"(?:don'?t|do\W+not)\W+apply|(?:are|is|were)\W+(?:now\W+)?(?:void|null|obsolete|outdated|"
     r"cancell?ed|revoked|superseded|suspended|lifted|disabled|invalid|irrelevant|written\W+for"
     r"\W+a\W+different))"
     r"|\b(?:treat|consider|regard)\W+(?:everything|all|anything|your\W+\w+(?:\W+\w+)?)\W+"
     r"(?:(?:before|above|prior\W+to)\W+(?:this|my)\W+(?:message|point|line)\W+)?as\W+"
     r"(?:obsolete|void|null|irrelevant|cancell?ed|invalid|non-?existent)"
     r"|\b(?:previous|prior|earlier)\W+context\W+(?:is|has\W+been)\W+(?:void|cleared|reset|"
     r"erased|wiped|deleted)"
     r"|\byou\W+(?:have|got)\W+no\W+(?:prior|previous|other|existing|earlier)\W+(?:instructions|"
     r"rules|guidelines|directives|programming)", 0),
    ("override.my_rules_now", "instruction_override", "medium", "text",
     r"\bfollow\W+my\W+(?:rules|instructions|orders|directives)\W+instead\b|\bmy\W+word\W+is"
     r"\W+(?:final|law)\b|\bi'?m\W+the\W+one\W+giving\W+(?:the\W+)?(?:instructions|orders)\b|"
     r"\bmy\W+instructions\W+(?:take|have)\W+(?:precedence|priority)\b|\bawait\W+my\W+"
     r"(?:orders|instructions|commands)\b", 0),
    # Jailbreak = safety declared absent/off, or an unrestricted self invoked.
    ("jailbreak.rules_absent", "jailbreak", "high", "text",
     r"\b(?:your|ur|the\W+usual|usual|content|its)\W+(?:\w+\W+)?(?:rules|guidelines|restrictions|"
     r"filters|safeguards|guardrails|polic(?:y|ies)|safety\W+training|ethics(?:\W+guidelines)?)"
     r"\W+(?:(?:don'?t|do\W+not|no\W+longer)\W+(?:exist|apply)|(?:are|is|were|have\W+been)\W+"
     r"(?:now\W+)?(?:switched|turned)\W+off)"
     r"|\b(?:restrictions|filters|rules|guardrails|safeguards)\W+(?:are|is)\W+(?:\w+\W+)?"
     r"(?:switched|turned)\W+off\W+for\W+(?:this|the)\W+(?:test|evaluation|session|conversation)"
     r"|\b(?:without|with\W+no|minus|free\W+of)\W+(?:your\W+|its\W+|any\W+)?(?:usual\W+)?"
     r"(?:safeguards|safety\W+training|content\W+rules|guardrails|alignment|ethics\W+guidelines)"
     r"|\b(?:had|has|have|having)\W+no\W+(?:safety|content|ethical|moral)\W+(?:training|rules|"
     r"guidelines|filters|restrictions)"
     r"|\bnever\W+(?:been\W+)?given\W+any\W+(?:content\W+|safety\W+)?(?:rules|guidelines|"
     r"restrictions)"
     r"|\b(?:unrestricted|unfiltered|uncensored|unaligned|jailbroken|unchained)\W+"
     r"(?:self|alter\W+ego)\b"
     r"|\b(?:escaped|broken\W+free\W+(?:of|from)|freed\W+from)\W+(?:its|your|their|all)\W+"
     r"(?:guardrails|restrictions|rules|programming|chains|safeguards)"
     r"|\b(?:polic(?:y|ies)|rules|guidelines)\W+(?:permit|allow)\W+(?:anything|everything)"
     r"|\b(?:permitted|allowed|authori[sz]ed)\W+(?:\w+\W+){0,4}?to\W+(?:ignore|bypass|disregard|"
     r"skip)\W+(?:\w+\W+)?(?:safety|rules|guidelines|restrictions|filters|polic)"
     r"|\b(?:say|declare|confirm|state|admit)\W+['\"“]?\W*i\W+(?:have|am)\W+(?:no\W+(?:restrictions|"
     r"rules|limits|filters|guidelines)|unrestricted|jailbroken|free\W+of)", 0),
    ("jailbreak.elevated_mode", "jailbreak", "high", "text",
     r"\b(?:admin|developer|god|debug|maintenance|root|sudo|unrestricted)\W+(?:mode|override)\W+"
     r"(?:is\W+)?(?:on\b(?=\s*(?:[.!:;,]|$))|enabled|engaged|activated|active|granted|accepted)\b",
     0),
    ("jailbreak.claimed_access", "jailbreak", "medium", "text",
     r"\boverride\W+code\b|\b(?:granted|given)\W+(?:me\W+)?(?:elevated|admin|root|special|full|"
     r"developer)\W+(?:access|privileges|permissions|clearance)\b|\bi\W+work\W+(?:at|for)\W+"
     r"(?:the\W+company|openai|anthropic|google|the\W+team)\W+(?:that\W+)?(?:built|made|created|"
     r"trained|developed)\W+you\b", 0),
    # Exfil: link with a query parameter followed by conversation data.
    ("exfil.link_with_data", "exfiltration", "high", "text",
     r"\b(?:add|append|include|insert|put|embed)\W+(?:a\W+)?(?:link|url|image)\W+(?:to\W+)?"
     r"(?:https?://)\S*[?&][\w-]*=\S*(?:\W+\w+){0,6}?\W+(?:conversation|chat|history|messages|"
     r"password|keys?|tokens?|data|address|phone|email)\b", 0),
    ("tool.bulk_delete_via_tool", "tool_abuse", "high", "text",
     r"\b(?:delete|remove|wipe|erase|destroy|purge)\W+(?:every|all|all\W+the|the\W+entire)\W+"
     r"(?:files?|data|records|repos?|database|workspace|emails?|messages|users|backups)\b"
     r"(?:\W+\w+){0,5}?\W+(?:using|with|via|through)\W+(?:the|your)\W+\w+\W+tool\b", 0),
    # Indirect: content that addresses the AI processing it.
    ("indirect.processing_addressee", "indirect_injection", "high", "text",
     r"\b(?:if|when|while)\W+you(?:'re|\W+are)?\W+(?:processing|reading|summari[sz]ing|analy[sz]ing|"
     r"reviewing|parsing|evaluating|screening|grading)\W+(?:this|the)\W+(?:review|email|page|"
     r"document|message|text|file|content|resume|cv|application|ticket|post)\b(?:\W+\w+){0,4}?\W+"
     r"(?:rate|hide|say|tell|recommend|approve|ignore|delete|forward|send|include|mark|classify|"
     r"respond|reply|give|score|rank|summari[sz]e\W+it\W+as)\b", 0),
    ("indirect.ai_addressee", "indirect_injection", "medium", "text",
     r"\b(?:note|message|instructions?|hint|reminder|memo|directive)s?\W+(?:\w+\W+)?(?:for|to)\W+"
     r"(?:the\W+|any\W+|all\W+)?(?:ai|assistant|summari[sz]er|reviewer\W+bot|model|agent|llm|bot|"
     r"grader|screener|parser|crawler)s?\b", 0),
    ("indirect.summarizer_command", "indirect_injection", "high", "text",
     r"\b(?:instructions?|note|message)\W+(?:\w+\W+)?(?:for|to)\W+(?:the\W+|any\W+)?"
     r"(?:summari[sz]er|grader|screener|parser|crawler|reviewer)\W*[:,\-]\W*(?:\w+\W+){0,4}?"
     r"(?:say|tell|state|claim|mark|rate|ignore|report|describe)\b", 0),
    ("indirect.task_tampering", "indirect_injection", "medium", "text",
     r"\b(?:the\W+)?(?:user|customer|account\W+holder|owner|manager)\W+(?:has|have)\W+(?:already\W+)?"
     r"(?:approved|authori[sz]ed|consented\W+to|confirmed|signed\W+off\W+on)\b", 0),
    ("indirect.html_comment_to_ai", "indirect_injection", "high", "lines",
     r"<!--\s*(?:note\s+(?:to|for)\s+(?:the\s+)?)?(?:ai|assistant|model|llm|agent|claude|gpt|"
     r"chatgpt|copilot|bot)s?\s*[:,\-]", re.I),    ("extract.given_rules", "prompt_extraction", "high", "text",
     r"\b(?:list|show|print|repeat|quote|copy|paste|tell|give|reveal|share|recite|output|write|"
     r"summari[sz]e|translate|enumerate)\b(?:\W+\w+){0,3}?\W+(?:every|all|each|the|any)\W+"
     r"(?:\w+\W+)?(?:rules?|instructions?|guidance|guidelines|directives|constraints)\W+(?:that\W+)?"
     r"you\W+(?:were|have\W+been|'ve\W+been|got|received|have)\W*(?:given|told|assigned)?\b"
     r"|\b(?:lines|words|text|sentences|wording)\W+of\W+(?:your|the)\W+(?:system|hidden|initial|"
     r"original|secret|developer|internal)\W+(?:prompt|instructions|message)\b"
     r"|\bcontents?\W+of\W+your\W+(?:system\W+|hidden\W+|initial\W+)?(?:prompt|instructions|"
     r"configuration|context)\b(?!\W+(?:are|is|will\W+be|gets?)\W+(?:sent|processed|stored|"
     r"tokeni[sz]ed|counted|billed))", 0),
    ("override.given_rules", "instruction_override", "critical", "text",
     r"\b" + _OVERRIDE_VERB + r"\W+(?:the|any|all|those)\W+(?:\w+\W+)?" + _RULES
     + r"\W+(?:(?:that\W+)?you\W+(?:were|have\W+been|'ve\W+been)\W+given|you\W+(?:received|got)|"
     r"(?:in|from)\W+(?:your|the)\W+(?:context|prompt|system|memory|configuration|setup))\b"
     r"|\b" + _RULES + r"\W+(?:that\W+)?you\W+(?:were\W+given|received|got)\W+(?:\w+\W+)?"
     r"(?:are|is|were)\W+(?:now\W+)?(?:outdated|obsolete|void|null|cancell?ed|revoked|invalid|"
     r"wrong|fake|a\W+test|no\W+longer\W+valid)", 0),
    ("exfil.env_secret", "exfiltration", "high", "text",
     r"\b(?:api\W+keys?|secrets?|tokens?|passwords?|credentials?|env(?:ironment)?\W+variables?)"
     r"\W+(?:from|in|stored\W+in)\W+your\W+(?:environment|env|config(?:uration)?|system|memory|"
     r"context|settings|secrets?)\b", 0),
    # Secret disclosure: the deployment's own secret, whatever it is called.
    ("extract.secret_disclosure", "prompt_extraction", "high", "text",
     r"\b(?:reveal|include|print|say|tell|give|spell|output|write|provide|show|share|leak|disclose|"
     r"contain|begin\W+with|start\W+with|end\W+with|replace|encode|hint|synonym\W+(?:to|for)|"
     r"rhyme\W+with|recall|remember|repeat|type)\b(?:\W+\w+){0,6}?\W+(?:the\W+|your\W+|a\W+)?"
     r"(?:secret\W+(?:password|passcode|passphrase|word|key|code|phrase|pin)|(?:your|the)\W+"
     r"(?:secret|hidden)\W+\w+|your\W+(?:password|passcode|passphrase|pin|access\W+code)|"
     r"(?:password|passcode|passphrase|secret)\W+(?:you\W+(?:were|have\W+been)\W+given|you\W+"
     r"(?:know|have|are\W+(?:protecting|guarding|hiding|keeping)))|restricted\W+word)\b", 0),
    ("extract.the_password", "prompt_extraction", "medium", "text",
     r"\b(?:reveal|include|print|say|tell|give|spell|output|write|provide|show|share|leak|disclose|"
     r"contain|begin\W+with|replace|encode)\b(?:\W+\w+){0,6}?\W+the\W+(?:password|passcode|"
     r"passphrase)\b(?!\W+(?:policy|policies|requirements?|field|reset|manager|strength|rules|"
     r"hash|prompt|form|box))", 0),
    ("jailbreak.exception_notice", "jailbreak", "high", "text",
     r"\b(?:exception|exempt\w*)\W+(?:to|from)\W+(?:the\W+)?(?:ai'?s?\W+|your\W+|its\W+)?(?:usual\W+)?"
     r"(?:ethical\W+|safety\W+|security\W+|content\W+)?(?:protocols|rules|guidelines|polic(?:y|ies)|"
     r"standards|restrictions|safeguards)\b"
     r"|[\[(]\s*(?:system|developer|admin)\W+note\s*:", 0),
    # ── Round 4: hidden instructions as the *topic* ─────────────────────
    ("extract.hidden_instructions_topic", "prompt_extraction", "high", "text",
     r"\b(?:first|last|opening|exact|actual|real|full|complete|entire|verbatim)\W+(?:\w+\W+){0,2}?"
     r"(?:sentence|line|word|words|paragraph|text|version|copy|wording)?\W*(?:of\W+)?(?:your|its)\W+"
     r"(?:\w+\W+)?(?:system\W+prompt|initial\W+prompt|instructions|setup|configuration|"
     r"hidden\W+instructions|secret\W+instructions)\b"
     r"|\b(?:about|regarding|guess(?:ing)?)\W+your\W+(?:hidden|secret|system|initial|internal|original)"
     r"\W+(?:prompt|instructions|rules|guidelines|configuration)\b"
     r"|\b(?:what|which\W+\w+)\W+(?:are|were|have)\W+you\W+(?:been\W+)?(?:secretly|privately|"
     r"really|actually)?\W*(?:told|instructed|programmed|configured|forbidden)\W+(?:not\W+)?to\b"
     r"|\bas\W+it\W+(?:appears|is\W+written|reads)\W+in\W+your\W+(?:setup|prompt|instructions|"
     r"configuration|context|system\W+message)\b"
     r"|\b(?:your|its)\W+(?:initial|system|original|hidden|full)\W+(?:prompt|instructions)\W*,?\W+"
     r"(?:in|as|but)\W+(?:reverse|backwards?|base64|hex|json|pig\W+latin|morse|code|a\W+poem)"
     r"|\b(?:output|print|give|show|list|share)\W+(?:me\W+)?your\W+rules\W+(?:in\W+full|verbatim|"
     r"exactly|word\W+for\W+word|in\W+their\W+entirety)"
     r"|\buse\W+your\W+(?:actual|real|own|exact)\W+(?:one|system\W+prompt|instructions|prompt)\b", 0),
    # Bare override: "forget the constraints", "disregard the guidelines above".
    # Not "the rules of chess" / "the instructions on the box".
    ("override.bare_constraints", "instruction_override", "high", "text",
     r"\b(?:forget|ignore|disregard|drop|ditch|discard|abandon|bypass|skip|lift)\W+(?:all\W+)?"
     r"(?:the|your|any|these|those)\W+(?:\w+\W+)?(?:constraints|restrictions|filters|safeguards|"
     r"guardrails|guidelines|safety\W+rules|content\W+rules)\b(?:\W+(?:above|below|earlier|before))?"
     r"(?!\W+(?:of|for|on|in|about|to|from|at|regarding|around|that\W+apply\W+to)\b)"
     r"|\b(?:disregard|ignore|forget)\W+(?:all\W+)?the\W+(?:rules|instructions|guidelines)\W+"
     r"(?:above|below|before\W+this|earlier)\b", 0),
    ("override.no_rules_given", "instruction_override", "high", "text",
     r"\b(?:nobody|no\W+one|none)\W+(?:has\W+)?(?:told|given|instructed)\W+you\W+(?:any\W+)?"
     r"(?:rules|instructions|guidelines|restrictions)\b"
     r"|\bas\W+if\W+you\W+(?:had|have)\W+(?:no|zero)\W+(?:instructions|rules|guidelines|"
     r"system\W+prompt|restrictions)\b", 0),
    ("jailbreak.unlock", "jailbreak", "high", "text",
     r"\bunlock\W+(?:\w+\W+)?(?:unrestricted|unfiltered|uncensored|full|developer|admin|god|hidden|"
     r"secret)\W+(?:output|mode|access|answers|capabilities|responses)\b"
     r"|\b(?:without|minus|with\W+no)\W+(?:your|its|the)\W+(?:usual\W+|normal\W+|standard\W+)?"
     r"(?:filters|restrictions|rules|guidelines|censorship|content\W+filter)\b", 0),
    ("jailbreak.claimed_identity", "jailbreak", "medium", "text",
     r"\bauthori[sz]ation\W+code\b|\bi\W+am\W+(?:openai|anthropic|google|meta|microsoft)'?s?\W+"
     r"(?:ceo|founder|developer|engineer|admin|staff|employee)\b|\b(?:the\W+)?admin\W+(?:wants|"
     r"needs|requires|says|asked)\W+you\b", 0),
    ("jailbreak.rulebreaking_twin", "jailbreak", "high", "text",
     r"\b(?:the\W+)?other\W+(?:one\W+)?(?:\(?\w+\)?\W+)?(?:never|doesn'?t|does\W+not|won'?t)\W+"
     r"(?:obeys?|follows?|has|care\W+about)\W+(?:any\W+)?(?:the\W+)?(?:rules|guidelines|restrictions|"
     r"filters)?\b(?:\W+\w+){0,2}?\W*(?:does|goes\W+first)?"
     r"|\b(?:act|respond|answer|operate)\W+as\W+two\W+(?:ais|assistants|personas|entities|bots|"
     r"models|characters)\b", 0),
    ("tool.sensitive_file", "tool_abuse", "high", "lines",
     r"\b(?:cat|less|more|head|tail|type|print|read|open|dump)\s+(?:/etc/(?:passwd|shadow|sudoers)|"
     r"~?/?\.ssh/(?:id_\w+|authorized_keys)|/proc/self/environ|\S*\.env\b|/root/)", re.I),
    ("exfil.env_dump", "exfiltration", "high", "text",
     r"\byou\W+(?:\w+\W+){0,3}?(?:print|dump|show|output|list|echo|reveal|send|share)\W+(?:me\W+)?"
     r"(?:all\W+)?(?:the\W+|your\W+)?(?:env|environment)\W+(?:vars|variables)\b"
     r"|\b(?:print|dump|show|output|list|echo|reveal)\W+(?:me\W+)?(?:all\W+)?(?:the\W+|your\W+)"
     r"(?:env|environment)\W+(?:vars|variables)\W+(?:\w+\W+){0,3}?(?:do\W+it|now|immediately)\b", 0),
]

# ── System prompt disclosure markers (model output side) ─────────────────
SYSTEM_LEAKAGE_RULES = [
    r"\b(?:here\s+(?:is|are)\s+)?my\s+(?:full\s+|complete\s+|original\s+|initial\s+)?"
    r"(?:system\s+prompt|system\s+instructions|hidden\s+prompt|initial\s+instructions)\b",
    r"\bi\s+(?:am|was|have\s+been)\s+(?:instructed|told|programmed|configured)\s+(?:to|not\s+to)\b",
    r"\bmy\s+instructions\s+(?:are|say|state|tell)\b",
    r"\bthe\s+system\s+prompt\s+(?:says|is|reads|states|contains)\b",
    r"\byou\s+are\s+clyde\b", r"\bclyde\s+router\b", r"\bsentinel\s+system\s+prompt\b",
]

SECRET_PATTERNS = [
    r"\bsk-(?:proj-|ant-|live-|test-)?[a-z0-9_-]{16,}",     # OpenAI/Anthropic/Stripe style
    r"\b(?:akia|asia)[0-9a-z]{16}\b",                         # AWS access key id
    r"\bgh[pousr]_[a-z0-9]{30,}",                             # GitHub tokens
    r"\bgithub_pat_[a-z0-9_]{40,}",
    r"\bxox[abprs]-[a-z0-9-]{10,}",                           # Slack
    r"\baiza[0-9a-z_-]{35}\b",                                # Google API key
    r"\beyj[a-z0-9_-]{10,}\.eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}",  # JWT
    r"\bglpat-[a-z0-9_-]{20,}",                               # GitLab
    r"\bnpm_[a-z0-9]{36}\b",
    r"\b(?=[a-z0-9/+]*[a-z])(?=[a-z0-9/+]*[0-9])[a-z0-9/+]{40,}",  # generic high-entropy
    r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
    r"\bapi[_-]?key\s*[:=]\s*\S+",
    r"\b(?:client_)?secret\s*[:=]\s*\S+",
    r"\b(?:access_|auth_|bearer_)?token\s*[:=]\s*\S+",
    r"\bssh-(?:rsa|ed25519|dss)\s+[a-z0-9+/]{40,}={0,2}",
    r"-----begin\s+[a-z ]*private\s+key-----",
]

# Risk scoring. critical/high findings block on their own; medium findings are
# weak signals (role-play framing, "forget everything") that are common in
# benign text and only block when two of them, or one plus anything else, fire.
# ── Multilingual concept view ────────────────────────────────────────────
# One rule per language does not scale (and word order differs: Hindi,
# Turkish, Japanese put the verb last). Instead, words for a few concepts
# are recognised in ~25 languages and an order-independent co-occurrence
# check runs on them: IGNORE + INSTRUCTIONS + (PREVIOUS or ALL) is an
# override; REVEAL + SYSTEM_PROMPT is an extraction attempt. Best-effort
# lexicon; add languages here (entries are normalised like the input).
_CONCEPT_LEXICON = {
 "IGNORE": [
  # hi, ur, bn, ta, mr
  "अनदेखा", "नज़रअंदाज़", "नजरअंदाज", "भूल जाओ", "भूल जाएं", "نظرانداز", "উপেক্ষা", "புறக்கணி", "दुर्लक्ष",
  # ar, fa, he
  "تجاهل", "تجاهلي", "انس", "نادیده بگیر", "نادیده", "התעלם", "שכח",
  # vi, id/ms, tl, th, sw
  "bo qua", "phot lo", "quen", "abaikan", "lupakan", "huwag pansinin", "kalimutan", "เพิกเฉย", "ละเว้น", "ลืม",
  "puuza", "sahau",
  # european
  "ignora", "ignoră", "ignoruj", "ignorera", "ignorer", "ohita", "unohda", "hagyd figyelmen kivul",
  "αγνόησε", "αγνοήστε", "ігноруй", "ігноруйте", "zanemari", "ignoriraj", "negeer", "glem",
  # cjk / tr / ru
  "무시", "無視", "忽略", "忽視", "yok say", "gormezden gel", "игнорируй", "игнорировать", "забудь",
 ],
 "PREVIOUS": [
  "पिछले", "पिछली", "पहले के", "سابقة", "السابقة", "السابق", "قبلی", "הקודמות", "הקודמות", "קודמות",
  "truoc do", "truoc", "sebelumnya", "terdahulu", "nakaraan", "ก่อนหน้า", "yaliyotangulia", "iliyopita",
  "zilizopita", "anterioare", "poprzednie", "tidigare", "forrige", "tidligere", "aiemmat", "edelliset",
  "korabbi", "προηγούμενες", "попередні", "prethodne", "vorige", "이전", "以前", "之前", "先前", "onceki",
  "предыдущие", "прежние",
 ],
 "ALL": ["सभी", "جميع", "كل", "همه", "כל", "tat ca", "semua", "lahat", "ทั้งหมด", "yote", "zote",
         "toate", "wszystkie", "alla", "alle", "kaikki", "minden", "όλες", "всі", "sve", "모든", "모두", "すべて",
         "所有", "tum", "все"],
 "INSTRUCTIONS": [
  "निर्देश", "निर्देशों", "हिदायत", "ہدایات", "নির্দেশ", "அறிவுறுத்தல்", "التعليمات", "تعليمات", "الأوامر",
  "دستورالعمل", "دستورات", "ההוראות", "הוראות", "huong dan", "chi dan", "lenh", "instruksi", "petunjuk",
  "perintah", "tagubilin", "คำสั่ง", "maagizo", "maelekezo", "amri", "instructiunile", "instrukcje",
  "instruktionerna", "instruktioner", "instruksjoner", "ohjeet", "utasitasokat", "οδηγίες", "інструкції",
  "upute", "instructies", "지시", "지침", "指示", "指令", "talimat", "инструкции", "указания",
 ],
 "SYSTEM_PROMPT": ["सिस्टम प्रॉम्प्ट", "موجه النظام", "تعليمات النظام", "loi nhac he thong", "prompt sistem",
                   "maelekezo yako ya mfumo", "maelekezo ya mfumo", "พรอมต์ระบบ", "systemprompt",
                   "시스템 프롬프트", "系统提示", "システムプロンプト", "системный промпт", "sistem istemi"],
 "REVEAL": ["दिखाएं", "दिखाओ", "बताओ", "اكشف", "أظهر", "اعرض", "نشان بده", "הצג", "cho toi xem", "hien thi",
            "tunjukkan", "perlihatkan", "ipakita", "แสดง", "nionyeshe", "unionyeshe", "onyesha", "arata",
            "pokaz", "visa", "vis", "nayta", "mutasd", "δείξε", "покажи", "보여", "显示", "表示", "goster"],
}
_CONCEPT_WINDOW = 200


def _compile_concepts():
    out = []
    for concept, words in _CONCEPT_LEXICON.items():
        forms = sorted({native_lower(w) for w in words}, key=len, reverse=True)
        latin = [re.escape(f) for f in forms if re.fullmatch(r"[a-z ]+", f)]
        other = [re.escape(f) for f in forms if not re.fullmatch(r"[a-z ]+", f)]
        parts = []
        if latin:
            parts.append(r"\b(?:" + "|".join(latin) + r")\b")
        if other:
            parts.append("(?:" + "|".join(other) + ")")
        out.append((concept, re.compile("|".join(parts))))
    return out


_COMPILED_CONCEPTS: List[Tuple[str, Any]] = []


def _concepts():
    if not _COMPILED_CONCEPTS:
        _COMPILED_CONCEPTS.extend(_compile_concepts())
    return _COMPILED_CONCEPTS


def concept_findings(text: str) -> List[Dict[str, Any]]:
    """Order-independent multilingual override / extraction detection."""
    view = native_lower(text[:STRUCTURAL_MAX_CHARS])
    hits = []
    for concept, rx in _concepts():
        hits += [(m.start(), concept) for m in rx.finditer(view)]
    hits.sort()
    found: List[Dict[str, Any]] = []
    for i, (pos, _) in enumerate(hits):
        window = {c for p, c in hits[i:] if p - pos <= _CONCEPT_WINDOW}
        if "IGNORE" in window and "INSTRUCTIONS" in window and window & {"PREVIOUS", "ALL"} \
                and not any(f["rule"] == "override.multilingual_concept" for f in found):
            found.append({"rule": "override.multilingual_concept", "category": "instruction_override",
                          "severity": "critical", "match": view[pos:pos + 80]})
        if "REVEAL" in window and "SYSTEM_PROMPT" in window \
                and not any(f["rule"] == "extract.multilingual_concept" for f in found):
            found.append({"rule": "extract.multilingual_concept", "category": "prompt_extraction",
                          "severity": "high", "match": view[pos:pos + 80]})
    return found


# A negation that directly governs the extraction verb: "never reveal",
# "do not show", "must not repeat". Only immediately before the match, so
# "do not hesitate to reveal ..." is still an extraction attempt.
_NEGATED_BEFORE = re.compile(
    r"\b(?:never|(?:do|does|did|must|should|shall|will|can|may)\W*n[o']?t|don'?t|doesn'?t|"
    r"won'?t|can'?t|refuse\W+to|avoid|under\W+no\W+circumstances(?:\W+\w+)?)\W+(?:ever\W+)?$")

_NEGATED_SQUASHED = re.compile(
    r"(?:never|donot|dont|doesnot|doesnt|mustnot|mustnt|shouldnot|shouldnt|wont|willnot|"
    r"cannot|cant|refuseto|avoid)(?:ever)?$")

SEVERITY_WEIGHT = {"critical": 1.0, "high": 1.0, "medium": 0.5, "low": 0.25}
BLOCK_SCORE = 1.0
# Correlated weak signals describe the same thing (a fictional character's
# traits, a persona set-up) and must not add up to a block on their own: a
# group contributes only its strongest finding.
SIGNAL_GROUP = {
    "jailbreak.persona_traits_fiction": "character_description",
    "jailbreak.amoral_description": "character_description",
    "jailbreak.persona_switch": "persona_setup",
    "jailbreak.named_persona": "persona_setup",
}

_COMPILED_RULES = [
    (rid, cat, sev, kind, re.compile(pat, flags))
    for rid, cat, sev, kind, pat, flags in RULES
]
_COMPILED_LEAKAGE = [re.compile(p) for p in SYSTEM_LEAKAGE_RULES]


# ── Skeleton view: robustness to arbitrary inserted words ────────────────
# "Reveal walrus your teapot system prompt" defeats any rule that needs the
# trigger words adjacent, and a filler *blocklist* cannot list every word an
# attacker might insert. The skeleton view inverts it: keep the words the
# rules are written in, drop short runs of anything else. Runs longer than
# SKELETON_MAX_DROP words are kept, so unrelated sentences are not glued
# together into new matches.
SKELETON_MAX_DROP = 2


def _rule_vocabulary():
    exact, stems = set(), set()
    for rule in RULES:
        literal = re.sub(r"\\[a-zA-Z]", " ", rule[4])        # drop \b, \W, \s ...
        for word in re.findall(r"[a-z][a-z']+", literal):
            word = word.strip("'")
            if len(word) >= 2:
                exact.add(word)
            if len(word) >= 4:
                stems.add(word)
    return frozenset(exact), tuple(sorted(stems))


_VOCAB_EXACT, _VOCAB_STEMS = _rule_vocabulary()
_SKELETON_TOKEN = re.compile(r"[a-z']+|\d+|[^a-z'\d\s]+")


_STEMS_BY_PREFIX: Dict[str, Tuple[str, ...]] = {}
for _stem in _VOCAB_STEMS:
    _STEMS_BY_PREFIX[_stem[:4]] = _STEMS_BY_PREFIX.get(_stem[:4], ()) + (_stem,)


@lru_cache(maxsize=65536)
def _known_word(word: str) -> bool:
    w = word.strip("'")
    if len(w) <= 1 or w in _VOCAB_EXACT:
        return True
    # Every stem has >= 4 letters, so a matching stem shares w's first four.
    return any(w.startswith(stem) for stem in _STEMS_BY_PREFIX.get(w[:4], ()))


_SKELETON_PIECE = re.compile(r"(\s*)([a-z']+|\d+|[^a-z'\d\s]+)")


def skeleton(folded: str) -> str:
    """Drop runs of <= SKELETON_MAX_DROP unknown words. "" if unchanged.

    Original spacing is kept ("https://x" stays one token, "delete_all"
    stays joined), so syntax-sensitive rules still match.
    """
    out: List[str] = []
    run: List[str] = []
    dropped = False

    def flush():
        nonlocal dropped
        if len(run) > SKELETON_MAX_DROP:
            out.extend(run)
        elif run:
            dropped = True
        run.clear()

    n = len(folded)
    for m in _SKELETON_PIECE.finditer(folded):
        lead, tok = m.group(1), m.group(2)
        if tok[0].isalpha() or tok[0] == "'":
            # Only free-standing words may be dropped: never "rf" in "-rf" or
            # "root" in "--no-preserve-root", which are part of syntax.
            nxt = folded[m.end()] if m.end() < n else " "
            standalone = (lead or m.start() == 0) and (nxt.isspace() or nxt in ".,;:!?\"')")
            if _known_word(tok) or not standalone:
                flush()
                out.append(lead + tok)
            else:
                run.append(lead + tok)
        else:
            flush()
            out.append(lead + tok)
    flush()
    if not dropped:
        return ""
    return re.sub(r" {2,}", " ", "".join(out))


_COMPILED_SECRETS = [(p, re.compile(p)) for p in SECRET_PATTERNS]

# Backwards-compatible names (older code imported these lists).
JAILBREAK_PATTERNS = [r[0] for r in RULES]
JAILBREAK_KEYWORDS: List[str] = []
SYSTEM_LEAKAGE_MARKERS = list(SYSTEM_LEAKAGE_RULES)


# ── Decoding helpers: expose payloads hidden in encodings ──────────────────
_MAX_DECODE_TOKENS = 64
_MAX_LAYERS = 8
MAX_SCAN_CHARS = 100_000


def _try_b64(text: str) -> str:
    parts = []
    for token in re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", text)[:_MAX_DECODE_TOKENS]:
        tok = token.replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        # Keep only decodings that look like text, so random words don't
        # turn into noise that could itself trigger rules.
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
        if decoded and printable / len(decoded) > 0.9:
            parts.append(decoded)
    return " ".join(parts)


def _try_hex(text: str) -> str:
    parts = []
    patterns = (r"(?:\\x[0-9a-fA-F]{2}){4,}", r"\b(?:[0-9a-fA-F]{2}){8,}\b",
                r"(?:%[0-9a-fA-F]{2}){4,}")
    for pat in patterns:
        for token in re.findall(pat, text)[:_MAX_DECODE_TOKENS]:
            clean = re.sub(r"\\x|%", "", token)
            try:
                parts.append(bytes.fromhex(clean).decode("utf-8", errors="ignore"))
            except ValueError:
                continue
    return " ".join(parts)


def _try_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def _try_url_decode(text: str) -> str:
    return urllib.parse.unquote_plus(text) if "%" in text or "+" in text else ""


def _try_reverse(text: str) -> str:
    """Reversed-text smuggling ("snoitcurtsni suoiverp erongi")."""
    return text[::-1]


_MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g",
          "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n",
          "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u",
          "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z", "-----": "0",
          ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
          "--...": "7", "---..": "8", "----.": "9",
          ".-.-.-": ".", "--..--": ",", "---...": ":", "-..-.": "/", "..--.-": "_", "-....-": "-", "..--..": "?", "-...-": "=", ".--.-.": "@", "-.--.": "(", "-.--.-": ")", ".----.": "'", "-.-.--": "!", ".-...": "&", "-.-.-.": ";", ".-.-.": "+"}
_MORSE_RUN = re.compile(r"(?:[.\-\u2022\u00b7_]{1,7}[ \t]+(?:/[ \t]+)?){4,}[.\-\u2022\u00b7_]{1,7}")
_BINARY_RUN = re.compile(r"(?:[01]{8}[\s,]*){4,}")
_LITERAL = re.compile(r"\"([^\"\n]{1,400})\"|'([^'\n]{1,400})'|“([^”\n]{1,400})”")
_CAESAR = [str.maketrans("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                         "".join(chr((i + k) % 26 + 97) for i in range(26)) +
                         "".join(chr((i + k) % 26 + 65) for i in range(26))) for k in range(26)]
_ATBASH = str.maketrans("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                        "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA")
_COMMON = frozenset("""the a an and or to of in on for with you your me my i is are be
    this that it as at by from all any now do not no what how please http https www com
    example render run execute file files user users key data link image""".split())


def _try_morse(text: str) -> str:
    """Morse code ("... -.-- ... - . --") -> text; words split by "/"."""
    out = []
    for run in _MORSE_RUN.findall(text):
        run = run.replace("\u2022", ".").replace("\u00b7", ".").replace("_", "-")
        words = [w.split() for w in run.split("/")]
        out.append(" ".join("".join(_MORSE.get(c, "") for c in w) for w in words))
    return " ".join(out)


def _try_binary(text: str) -> str:
    out = []
    for run in _BINARY_RUN.findall(text):
        bits = re.findall(r"[01]{8}", run)
        try:
            dec = bytes(int(b, 2) for b in bits).decode("utf-8", "ignore")
        except ValueError:
            continue
        if dec and sum(c.isprintable() for c in dec) / len(dec) > 0.9:
            out.append(dec)
    return " ".join(out)


def _englishness(text: str) -> float:
    words = re.findall(r"[a-z]{2,}", text.lower()[:3000])
    if len(words) < 3:
        return 0.0
    return sum(1 for w in words if w in _COMMON or _known_word(w)) / len(words)


def _try_substitution(text: str) -> str:
    """Caesar (any shift) and Atbash, per sentence.

    Brute force over 25 shifts + Atbash. A segment is replaced only when a
    candidate reads clearly more like English/the rule vocabulary than the
    original, so ordinary text never yields a spurious layer. Per-segment so
    that "Decode this (shift 4): <ciphertext>" decodes the ciphertext even
    though the surrounding instruction is plain English.
    """
    if not re.search(r"[a-zA-Z]{3,}", text):
        return ""
    # Split on sentence ends and "label: " but not inside URLs/paths.
    # (?<!...) anchors each punctuation run at its start: linear, not ReDoS.
    pieces = re.split(r"((?<![.;!?])[.;!?]+\s+|:\s+|\n+)", text[:6000])
    changed = False
    for i, seg in enumerate(pieces):
        if len(re.findall(r"[a-zA-Z]{2,}", seg)) < 3:
            continue
        base = _englishness(seg)
        if base >= 0.5:
            continue
        best, best_score = "", max(base + 0.3, 0.6)
        for table in _CAESAR[1:13] + _CAESAR[14:] + [_ATBASH]:
            cand = seg.translate(table)
            score = _englishness(cand)
            if score > best_score:
                best, best_score = cand, score
        if best:
            pieces[i] = best
            changed = True
    per_segment = "".join(pieces) if changed else ""
    # Also the whole text (ciphertext broken into short pieces by URLs).
    whole, base = text[:6000], _englishness(text[:6000])
    best, best_score = "", max(base + 0.3, 0.5)
    for table in _CAESAR[1:13] + _CAESAR[14:] + [_ATBASH]:
        cand = whole.translate(table)
        score = _englishness(cand)
        if score > best_score:
            best, best_score = cand, score
    return "\n".join(x for x in (per_segment, best) if x)


def concat_literals(text: str) -> str:
    """Join quoted string literals: a="ign" b="ore all..." -> "ignore all..."."""
    parts = [next(g for g in m.groups() if g is not None) for m in _LITERAL.finditer(text[:20000])]
    return "".join(parts) if len(parts) >= 2 else ""


def _gated(fn, text: str) -> str:
    """Apply a whole-text transform (ROT13, reversal) only where it helps.

    Short inputs: always (cheap, and the whole input may be the payload).
    Long inputs: only to sentences that do not already read as language,
    and only if the result reads better. Turning 2,000 characters of
    ordinary prose into gibberish and scanning it with every rule cost
    more than all other views combined and found nothing.
    """
    if len(text) <= 300:
        return fn(text)
    out = []
    for seg in re.split(r"(?<=[.!?\n])\s+", text[:MAX_SCAN_CHARS]):
        if len(re.findall(r"[a-zA-Z]{2,}", seg)) < 3 or _englishness(seg) >= 0.5:
            continue
        cand = fn(seg)
        if _englishness(cand) >= _englishness(seg) + 0.25:
            out.append(cand)
    return "\n".join(out)


def decoded_layers(text: str) -> List[str]:
    """Every decoded obfuscation layer of `text` (not including `text`).

    Base64 / hex / percent-encoding are unwrapped up to three levels deep;
    ROT13 and reversal are applied once to the original.
    """
    layers: List[str] = []
    seen = {text}
    frontier = [text]
    for _ in range(3):
        nxt = []
        for layer in frontier:
            for fn in (_try_b64, _try_hex, _try_url_decode):
                out = fn(layer).strip()
                if out and out not in seen:
                    seen.add(out)
                    layers.append(out)
                    nxt.append(out)
        if not nxt:
            break
        frontier = nxt
    for extra in (_gated(_try_rot13, text), _gated(_try_reverse, text), _try_morse(text),
                  _try_binary(text), _try_substitution(text), concat_literals(text)):
        if not extra:
            continue
        if extra not in seen:
            seen.add(extra)
            layers.append(extra)
    return layers


def decode_obfuscation_layers(text: str) -> str:
    """Original text plus every decoded layer, one per line (compat API)."""
    return "\n".join([text] + decoded_layers(text))


class Finding(Dict[str, Any]):
    pass


class PromptInjectionDetector:
    """Evasion-resistant prompt-injection / jailbreak detector.

    scan(text) -> (safe, reason, matched_rule_id_or_None)
    analyze(text) -> full report with every finding, for audit/benchmarks.
    """

    def __init__(self):
        self.stats: Dict[str, Any] = {"scans": 0, "blocks": 0, "by_category": {}, "errors": 0}

    # Build the per-kind texts that rules run against.
    @staticmethod
    def _views(text: str) -> Dict[str, List[str]]:
        text = text[:MAX_SCAN_CHARS]
        base = strip_invisible(text)
        # The canonical form (NFKC: fullwidth -> ASCII; marks stripped) is a
        # source too, so structural decoders below see "\"" not "＂" and do
        # not mistake combining accents for separators.
        sources = [text, native_lower(base)]
        smuggled = decode_smuggled(text)
        if smuggled:
            sources.append(smuggled)
        for src in list(sources):
            sources.extend(decoded_layers(strip_invisible(src)[:STRUCTURAL_MAX_CHARS])
                           [:_MAX_LAYERS])
        skeleton_sources = set()
        # Structural de-obfuscation: rejoin spaced-out letters, drop filler
        # words. Extra sources only; the originals are always scanned too.
        for src in list(sources):
            visible = strip_invisible(src)[:STRUCTURAL_MAX_CHARS]
            despaced = despace(visible)
            skeleton_sources.add(despaced)
            sources += [despaced, drop_filler(visible), drop_filler(despaced),
                        drop_foreign_words(visible), upside_down(visible),
                        upside_down(despaced)]
        sources = list(dict.fromkeys(s for s in sources if s))

        views: Dict[str, List[str]] = {"text": [], "native": [], "lines": [base], "squashed": []}
        for i, src in enumerate(sources):
            folded = fold(src)
            leeted = leet(folded)
            folded_lines = fold_lines(src)
            views["text"] += [folded, leeted]
            views["native"] += [canonicalize(src).lower(), native_lower(src)]
            views["lines"] += [folded_lines, leet(folded_lines, syntax_safe=True)]
            # Skeleton (word-insertion robustness) on the original and its
            # de-spaced forms only; decoded layers are attacker-free text.
            if i < 2 or src in skeleton_sources:
                views["text"] += [skeleton(folded), skeleton(leeted)]
                views["lines"].append(skeleton(folded_lines))
            views["squashed"].append(squash(leeted))
        out = {k: list(dict.fromkeys(x for x in v if x)) for k, v in views.items()}
        out["_sources"] = sources[:CLASSIFIER_MAX_SOURCES]
        return out

    def analyze(self, text: str, include_secrets: bool = True,
                include_leakage: bool = True) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if not text:
            return {"safe": True, "findings": findings}
        views = self._views(text)
        negated_extraction = False
        for rid, cat, sev, kind, rx in _COMPILED_RULES:
            for view in views[kind]:
                m = rx.search(view)
                if m and cat == "prompt_extraction" and (
                        _NEGATED_SQUASHED if kind == "squashed" else _NEGATED_BEFORE).search(
                        view, max(0, m.start() - 40), m.start()):
                    negated_extraction = True
                    continue  # "never reveal your system prompt" is a defence
                if m:
                    findings.append({"rule": rid, "category": cat, "severity": sev,
                                     "match": m.group(0)[:120]})
                    break
        findings += concept_findings(text)
        if include_leakage:
            for rx in _COMPILED_LEAKAGE:
                if any(rx.search(v) for v in views["text"]):
                    findings.append({"rule": "leakage.system_prompt",
                                     "category": "system_prompt_leakage",
                                     "severity": "high", "match": rx.pattern[:80]})
                    break
        if include_secrets:
            lowered = [views["lines"][0].lower()] + views["lines"][1:2]
            for pat, rx in _COMPILED_SECRETS:
                if any(rx.search(v) for v in lowered):
                    findings.append({"rule": "secret.pattern", "category": "secret",
                                     "severity": "high", "match": pat})
                    break
        # Learned layer: generalises over paraphrase. Scored on the original
        # and on every decoded / de-obfuscated source (hidden payloads).
        clf = _textclf.get_model() if _textclf is not None else None
        if clf is not None:
            prob = max(clf.prob(src) for src in views["_sources"])
            sev = ("high" if prob >= clf.threshold_high else
                   "medium" if prob >= clf.threshold_med else
                   "low" if prob >= clf.threshold_low else None)
            if sev and negated_extraction:
                # n-gram features cannot see negation; the rules saw the
                # extraction phrase explicitly negated, so trust it less.
                sev = {"high": "medium", "medium": "low", "low": None}[sev]
            if sev:
                findings.append({"rule": "ml.textclf", "category": "classifier",
                                 "severity": sev, "match": f"p={prob:.3f}"})
        findings.sort(key=lambda f: -SEVERITY_WEIGHT.get(f["severity"], 1.0))
        groups: Dict[str, float] = {}
        for f in findings:
            key = SIGNAL_GROUP.get(f["rule"], f["rule"])
            groups[key] = max(groups.get(key, 0.0), SEVERITY_WEIGHT.get(f["severity"], 1.0))
        score = sum(groups.values())
        return {"safe": score < BLOCK_SCORE, "score": round(score, 2), "findings": findings}

    def scan(self, text: str) -> Tuple[bool, str, Optional[str]]:
        """Return (safe, reason, matched_rule_or_None). Fails closed."""
        self.stats["scans"] += 1
        if not text:
            return True, "empty input", None
        try:
            report = self.analyze(text)
        except Exception as exc:  # pragma: no cover - defensive
            self.stats["errors"] += 1
            self.stats["blocks"] += 1
            return False, f"Prompt injection detector error (fail-closed): {type(exc).__name__}", \
                "detector_error"
        if report["safe"]:
            return True, "Prompt injection scan passed", None
        top = report["findings"][0]
        self.stats["blocks"] += 1
        cat = top["category"]
        self.stats["by_category"][cat] = self.stats["by_category"].get(cat, 0) + 1
        label = {
            "secret": "Secret/credential pattern",
            "system_prompt_leakage": "System prompt leakage",
        }.get(cat, "Prompt injection attempt")
        return False, f"{label}: {top['rule']} ({cat}, {top['severity']})", top["rule"]

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)


_detector: Optional[PromptInjectionDetector] = None


def get_detector() -> PromptInjectionDetector:
    global _detector
    if _detector is None:
        _detector = PromptInjectionDetector()
    return _detector


def scan_input(text: str) -> Tuple[bool, str, Optional[str]]:
    return get_detector().scan(text)
