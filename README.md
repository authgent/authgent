# gh-pages

This branch hosts static artifacts the GitHub Pages site
serves under <https://authgent.github.io/authgent/>, plus
read-only fallbacks for the API endpoints (used when the
Oracle backend is unreachable).

- `registry-snapshot.json` -- automated snapshot of
  `/api/registry` updated every 6 hours by
  `.github/workflows/registry-snapshot.yml`.
