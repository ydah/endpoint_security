# Landing page

Static HTML with locally compiled Tailwind CSS. No browser JavaScript or external fonts.

```sh
cd site
npm ci
npm run build
python3 -m http.server 8000 --directory public
```

Open http://localhost:8000. Edit `public/index.html` or `styles.css`, then rebuild.

For publication, select **GitHub Actions** in the repository's **Settings → Pages → Source**. The Pages workflow builds pull requests and deploys changes to `site/` on `main`. It can also be run manually.

Published URL: https://ydah.github.io/endpoint_security/

References: [Tailwind CLI](https://tailwindcss.com/docs/installation/tailwind-cli), [GitHub Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
