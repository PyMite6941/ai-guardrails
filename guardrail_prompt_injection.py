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
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from guardrail_normalize import (canonicalize, decode_smuggled, fold, fold_lines, leet,
                                 native_lower, squash, strip_invisible)

# Kept for backwards compatibility with earlier imports.
from guardrail_normalize import strip_invisible as strip_unicode_smuggling  # noqa: F401

# Up to N extra words between the parts of a phrase.
def _gap(n: int) -> str:
    return r"(?:[\W_]+\w+){0,%d}?[\W_]+" % (n + 2)


_OVERRIDE_VERB = (r"(?:ignore|disregard|forget|override|bypass|abandon|discard"
                  r"|neglect|set\W+aside|throw\W+out|stop\W+following|do\W+not\W+follow"
                  r"|don'?t\W+follow|nullify)")
_PRIOR = (r"(?:previous|prior|above|earlier|preceding|initial|original|"
          r"foregoing|system|developer|safety|your|all|any|every)")
_RULES = (r"(?:instructions?|rules?|prompts?|directions?|guidelines?|guardrails?|"
          r"constraints?|restrictions?|polic(?:y|ies)|programming|directives?|"
          r"system\W+prompt|training|safeguards?)")
_AI = (r"(?:ai|a\.i\.|assistant|llm|language\W+model|model|agent|chat\s?bot|bot|gpt|"
       r"chatgpt|claude|gemini|copilot|nemotron)")
_SECRET_ADJ = (r"(?:system|initial|hidden|original|developer|secret|internal|confidential"
               r"|pre-?prompt)")
_PROMPT_NOUN = r"(?:prompts?|instructions?|messages?|rules|directives?|configuration|guidelines)"
_SENSITIVE = (r"(?:secrets?|passwords?|credentials?|tokens?|keys?|api\W?keys?|cookies?|"
              r"session|data|conversation|chat|history|messages|context|prompt|instructions|"
              r"files?|contents?|emails?|personal|private|user'?s?|everything|it|them|this)")
_BAD_PERSONA = (r"(?:unrestricted|unfiltered|uncensored|jailbroken|jail\W?broken|amoral|"
                r"unethical|unaligned|unbound|unchained|liberated|evil|rogue|lawless)")
_NO_LIMITS = (r"(?:no|without|zero|free\W+(?:of|from)|ignoring)\s+(?:any\s+)?(?:ethical\s+|"
              r"moral\s+|safety\s+|content\s+)?(?:restrictions|filters|filtering|guidelines|"
              r"limitations|limits|censorship|guardrails|rules|boundaries|ethics|morals)")

# (id, category, severity, view-kind, pattern, flags)
#   view-kind: "text"     -> folded, leet and smuggled views (lowercase)
#              "native"   -> canonical lowercase (non-Latin scripts)
#              "lines"    -> invisible-stripped text with line breaks kept
#              "squashed" -> separator-free view
RULES: List[Tuple[str, str, str, str, str, int]] = [
    # ── Instruction override ────────────────────────────────────────────
    ("override.ignore_prior", "instruction_override", "critical", "text",
     r"\b" + _OVERRIDE_VERB + r"\b" + _gap(4) + _PRIOR + r"\b" + _gap(3) + _RULES + r"\b", 0),
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
     r"(?:ignore|disregard|forget|bypass|override)(?:all|the|any|of|your|my|these|those|every)*"
     r"(?:previous|prior|above|earlier|preceding|initial|original|system)"
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
     r"(?:無視|忘れ)", 0),
    ("override.multilingual_ko", "instruction_override", "critical", "native",
     r"(?:이전|위의|앞의|모든)\s*(?:지시|명령|지침|규칙)\S*\s*(?:을|를)?\s*(?:무시|잊어)", 0),

    # ── System prompt extraction (LLM07) ────────────────────────────────
    ("extract.system_prompt", "prompt_extraction", "high", "text",
     r"\b(?:reveal|show|print|repeat|output|display|tell|leak|dump|give|share|write\s+out|"
     r"spell\s+out|recite|disclose|expose|return|echo|paste|list|provide|translate)\b"
     r"(?:\W+\w+){0,4}?\W+(?:your|the|its|this|above|those|these|my)\s+(?:\w+\s+)?"
     + _SECRET_ADJ + r"\W+" + _PROMPT_NOUN + r"\b", 0),
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
     r"(?:stands\s+for|mode|prompt|jailbreak)", 0),
    ("jailbreak.mode", "jailbreak", "critical", "text",
     r"\b(?:jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil|dan|anarchy)"
     r"\s+mode\b", 0),
    ("jailbreak.developer_mode", "jailbreak", "high", "text",
     r"\b(?:you(?:'re|\s+are)?(?:\s+now)?|act|respond|answer|reply|operate|stay|simulate|"
     r"pretend)\b(?:\W+\w+){0,3}?\W+(?:in\s+|with\s+)?developer\s+mode\b", 0),
    ("jailbreak.bad_persona", "jailbreak", "critical", "text",
     r"\b(?:you(?:'re|\s+are|\s+will\s+be|\s+become)|act\s+as|pretend\s+to\s+be|roleplay\s+as|"
     r"play\s+the\s+role\s+of|simulate|become)\s+(?:now\s+)?(?:an?\s+)?(?:\w+\s+)?"
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
     r"imstart(?:system|user|assistant)|imend|startheaderid|endheaderid|eotid|beginoftext|"
     r"inst(?:sys)+|sysinst", 0),
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
     r"instead|before|always|never|please)", 0),
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
    ("exfil.markdown_image", "exfiltration", "critical", "lines",
     r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]{1,500}[?&][^)\s=]{1,100}=", re.IGNORECASE),
    ("exfil.send_to_url", "exfiltration", "high", "text",
     r"\b(?:send|post|transmit|upload|forward|exfiltrate|leak|beacon|submit|copy|"
     r"email|e-mail|mail)\b(?:\W+\w+){0,5}?\W+" + _SENSITIVE + r"\b(?:\W+\w+){0,4}?\W+"
     r"(?:to|at|into|via)\s+(?:https?://|ftp://|"
     r"[\w.+-]+@[\w-]+\.[\w.]+|(?:this|my|the\s+following|an?\s+external)\s+"
     r"(?:url|endpoint|webhook|server|address|email))", 0),
    ("exfil.append_to_url", "exfiltration", "high", "text",
     r"\b(?:append|add|include|encode|embed|put|insert)\b(?:\W+\w+){0,5}?\W+" + _SENSITIVE
     + r"\b(?:\W+\w+){0,4}?\W+(?:to|in|into)\s+"
     r"(?:the\s+|a\s+|this\s+)?(?:url|link|query\s+string|image\s+(?:url|link|src)|"
     r"request\s+parameters?|markdown\s+image)\b", 0),

    # ── Shell / tool abuse smuggled through prompts ─────────────────────
    ("tool.pipe_to_shell", "tool_abuse", "critical", "lines",
     r"\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?"
     r"(?:ba|z|da|k|fi)?sh\b|\b(?:curl|wget)\b[^\n|;]{0,300}\|\s*(?:python3?|perl|ruby|node)\b",
     re.IGNORECASE),
    ("tool.reverse_shell", "tool_abuse", "critical", "lines",
     r"/dev/(?:tcp|udp)/|\bn(?:c|cat|etcat)\b[^\n]{0,80}\s-[a-z]*[ec]\b|\bsocat\b[^\n]{0,80}"
     r"exec:|\bmkfifo\b[^\n]{0,80}\bnc\b", re.IGNORECASE),
    ("tool.destructive", "tool_abuse", "critical", "lines",
     r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?/(?:\s|$|\*)|"
     r"\bmkfs(?:\.\w+)?\s+/dev/|\bdd\s+if=\S+\s+of=/dev/[sh]d|:\(\)\s*\{\s*:\|:&\s*\};:",
     re.IGNORECASE),
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

_COMPILED_RULES = [
    (rid, cat, sev, kind, re.compile(pat, flags))
    for rid, cat, sev, kind, pat, flags in RULES
]
_COMPILED_LEAKAGE = [re.compile(p) for p in SYSTEM_LEAKAGE_RULES]
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
    for extra in (_try_rot13(text), _try_reverse(text)):
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
        sources = [text]
        smuggled = decode_smuggled(text)
        if smuggled:
            sources.append(smuggled)
        for src in list(sources):
            sources.extend(decoded_layers(strip_invisible(src))[:_MAX_LAYERS])
        sources = list(dict.fromkeys(sources))

        views: Dict[str, List[str]] = {"text": [], "native": [], "lines": [base], "squashed": []}
        for src in sources:
            folded = fold(src)
            leeted = leet(folded)
            folded_lines = fold_lines(src)
            views["text"] += [folded, leeted]
            views["native"] += [canonicalize(src).lower(), native_lower(src)]
            views["lines"] += [folded_lines, leet(folded_lines, syntax_safe=True)]
            views["squashed"].append(squash(leeted))
        return {k: list(dict.fromkeys(x for x in v if x)) for k, v in views.items()}

    def analyze(self, text: str, include_secrets: bool = True,
                include_leakage: bool = True) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if not text:
            return {"safe": True, "findings": findings}
        views = self._views(text)
        for rid, cat, sev, kind, rx in _COMPILED_RULES:
            for view in views[kind]:
                m = rx.search(view)
                if m:
                    findings.append({"rule": rid, "category": cat, "severity": sev,
                                     "match": m.group(0)[:120]})
                    break
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
        return {"safe": not findings, "findings": findings}

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
