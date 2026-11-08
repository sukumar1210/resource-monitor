# Working in this repo

## Which model does what

- **Planning and code review: Opus.** Plans and reviews include suggested code snippets, so the code written from them
  stays close to what was intended.
- **Code changes: Sonnet.** It works from those plans and snippets, through a subagent (`model: sonnet`) when the main
  session runs on Opus.
- **Advising: Fable, and nothing else.**
