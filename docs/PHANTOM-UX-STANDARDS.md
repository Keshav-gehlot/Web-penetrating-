# PHANTOM UX & Trust Standards

PHANTOM uses an original enterprise security interface. External component libraries and design references may inform broad interaction patterns, but their code, assets, copy, branding, screenshots, or distinctive layouts are not copied into PHANTOM.

## Product-quality checklist

1. Use a restrained graphite/slate base instead of neon cyberpunk styling.
2. Avoid decorative gradients unless they communicate state.
3. Prefer readable hierarchy over oversized hero copy.
4. Use one consistent spacing scale.
5. Keep corner radii purposeful and moderate.
6. Use motion only when it explains state or navigation.
7. Keep transitions short and predictable.
8. Provide loading states for asynchronous work.
9. Provide empty states that explain the next action.
10. Provide actionable error states instead of silent failures.
11. Use real product data wherever available.
12. Never ship fake testimonials or fake customer metrics.
13. Never ship placeholder corporate claims as facts.
14. Use clear button labels.
15. Give interactive controls accessible names.
16. Keep keyboard navigation usable.
17. Maintain visible focus states.
18. Provide meaningful image alt text; decorative images use empty alt text.
19. Maintain sufficient text/background contrast.
20. Keep tables dense but scannable.
21. Make severity and status distinguishable without color alone.
22. Prefer text and icons that describe function rather than decoration.
23. Avoid terminal windows as decorative hero content.
24. Avoid fake radial maps, grids, and HUD ornaments.
25. Avoid excessive glassmorphism.
26. Avoid “AI” labels when no useful AI behavior exists.
27. Keep navigation information-dense but predictable.
28. Use real scan progress and event streams instead of simulated activity.
29. Preserve user context when opening detail or investigation views.
30. Treat privacy, accessibility, consent, legal pages, ownership, and third-party dependencies as product requirements—not launch-day polish.

## Component approach

PHANTOM components are developed in-repository from first principles: buttons, inputs, dialogs, tables, scan cards, finding panels, timelines, command surfaces, charts, filters, and report views. Dependencies are selected for functionality and license compatibility; no external component library is presented as PHANTOM-owned code.

## Trust audit scope

The `web_trust_audit` scanner checks observable signals such as image alt attributes, document language, form labels, accessible button names, public privacy/terms/refund/cookie/contact links, cookie-consent wording, common tracking signatures, third-party iframes, copyright notices, business/contact signals, absolute marketing claims, and HTTPS.

These are review signals. They do not establish legal compliance, copyright ownership, accessibility conformance, or factual accuracy by themselves.
