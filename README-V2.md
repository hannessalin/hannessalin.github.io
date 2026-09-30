# hannessalin.github.io — v2 preview

A lightweight Jekyll/GitHub Pages redesign. No Node, React, database or server is required.

## Install

1. Back up your existing repository.
2. Copy these files into the root of `hannessalin.github.io`.
3. Keep your existing `hannes-du-profile.jpeg` and `roles.md`.
4. Commit and push to `main`.
5. GitHub Pages should rebuild automatically.

## What works immediately

- Responsive redesigned homepage
- Research metric cards reading JSON with JavaScript
- Separate publications page
- Search and category filtering
- Existing `roles.md` remains linked
- Mobile layout

## Scholar metrics

`assets/data/research-stats.json` intentionally contains placeholders. This avoids publishing invented citation metrics.

The included workflow is a safe scaffold. To make metrics automatic, connect a supported Scholar data source/provider and have the workflow overwrite `assets/data/research-stats.json`. Store API credentials in GitHub Actions Secrets, never in JavaScript or the repository.

Google Scholar profile ID: `yh4HgFMAAAAJ`.

## Next iteration

Move the complete publication list into `_data/publications.yml`, render it through Jekyll, add citation history, and optionally split supervision/talks/education into dedicated pages.
