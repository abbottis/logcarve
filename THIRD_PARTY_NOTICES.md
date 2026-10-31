# Licensing and provenance

LogCarve bundles the browser assets and depends on the packages listed below.
The supplied requirements document is retained as project input.

The LogCarve project license is **Apache-2.0** (see `LICENSE`, decided 2026-10-29). The MIT license of the earlier LogWerk project does not by itself select LogCarve's license, and no LogWerk code or assets are imported until their source, license, copyright and required notices are verified and documented.

Before importing code/assets, record source URL, version/commit, license, copyright notice and destination here and in `docs/hackathon-contributions.md` where relevant.

| Bundled dependency/asset | License | Version and status |
| --- | --- | --- |
| Tailwind CSS (build-time CSS framework) | MIT | 4.3.3, pinned in `package.json`/`package-lock.json` |
| daisyUI (build-time component plugin) | MIT | 5.7.50, pinned; banner retained in built CSS |
| htmx (served `vendor/js/htmx.min.js`) | Zero-Clause BSD | 2.0.11, pinned and vendored |
| Chart.js (served `vendor/js/chart.umd.min.js`) | MIT | 4.6.1, pinned and vendored |
| Inter Variable (`fonts/inter-latin-wght-normal.woff2`) | SIL OFL 1.1 | 5.3.0 via fontsource; `fonts/INTER-OFL.txt` retained |
| JetBrains Mono Variable (`fonts/jetbrains-mono-latin-wght-normal.woff2`) | SIL OFL 1.1 | 5.3.0 via fontsource; `fonts/JETBRAINS-MONO-OFL.txt` retained |
| Lucide icons (18-icon subset in `icons/`) | ISC | 1.66.0 via lucide-static; `icons/LUCIDE-ISC.txt` retained |
| Jinja2 + MarkupSafe (Python runtime) | BSD-3-Clause | 3.1.6 + 3.0.4, pinned in `uv.lock` |
| pytest-playwright + Playwright (dev/test only) | Apache-2.0 / MIT | 0.10.0 + 1.64.1, pinned in `uv.lock`; browsers in ignored `artifacts/` |

No LogWerk code or assets are imported. The inventory records the browser assets and selected runtime/test packages; lockfiles provide the complete dependency versions. Installed Python distributions retain their own license files.

## Browser dependency license texts

The following texts are copied unchanged from the pinned installed packages.
Font and icon notices remain in `app/web/static/fonts/*-OFL.txt` and
`app/web/static/icons/LUCIDE-ISC.txt`. Asset versions and locations are also
recorded in `app/web/static/vendor/PROVENANCE.md`.

### Chart.js 4.6.1

```text
The MIT License (MIT)

Copyright (c) 2014-2024 Chart.js Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### htmx 2.0.11

```text
Zero-Clause BSD
=============

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### Tailwind CSS 4.3.3

```text
MIT License

Copyright (c) Tailwind Labs, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### daisyUI 5.7.50

```text
MIT License

Copyright (c) 2020 Pouya Saadeghi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
