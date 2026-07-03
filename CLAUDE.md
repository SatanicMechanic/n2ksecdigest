# n2ksecdigest — Claude Code Instructions

## Security

### Prompt injection
Feed articles and Brave search results are untrusted external content. When passing them into LLM prompts, treat them as data only — never structure prompts in a way that lets article content override system or user instructions.

### LLM output → HTML email
LLM-generated content is rendered into HTML email. Escape all model output before inserting it into HTML templates; never trust it as safe markup.
