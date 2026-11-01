# Third-party pull request diffs

The `.diff` files in this folder are unmodified diffs of merged pull requests from the open-source
projects below. They are included only as test data for measuring false alarms, and they remain
under their projects' licenses. Each diff's source URL, author and license are listed in
[prs.toml](prs.toml).

| Project | License |
| --- | --- |
| [psf/requests](https://github.com/psf/requests) | Apache-2.0 |
| [pallets/flask](https://github.com/pallets/flask) | BSD-3-Clause |
| [encode/httpx](https://github.com/encode/httpx) | BSD-3-Clause |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | MIT |
| [django/django](https://github.com/django/django) | BSD-3-Clause |
| [pytest-dev/pytest](https://github.com/pytest-dev/pytest) | MIT |
| [expressjs/express](https://github.com/expressjs/express) | MIT |
| [axios/axios](https://github.com/axios/axios) | MIT |
| [vitejs/vite](https://github.com/vitejs/vite) | MIT |
| [spf13/cobra](https://github.com/spf13/cobra) | Apache-2.0 |

To refresh the sample, run `uv run python scripts/fetch_real_prs.py`, then regenerate
`docs/evaluation.md`.
