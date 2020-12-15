tuft.py [![Unlicensed work](https://raw.githubusercontent.com/unlicense/unlicense.org/master/static/favicon.png)](https://unlicense.org/)
=======
~~[wheel (GitLab)](https://gitlab.com/KOLANICH-libs/tuft.py/-/jobs/artifacts/master/raw/dist/tuft-0.CI-py3-none-any.whl?job=build)~~
[wheel (GHA via `nightly.link`)](https://nightly.link/KOLANICH-libs/tuft.py/workflows/CI/master/tuft-0.CI-py3-none-any.whl)
~~![GitLab Build Status](https://gitlab.com/KOLANICH-libs/tuft.py/badges/master/pipeline.svg)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH-libs/tuft.py/badges/master/coverage.svg)~~
[![GitHub Actions](https://github.com/KOLANICH-libs/tuft.py/workflows/CI/badge.svg)](https://github.com/KOLANICH-libs/tuft.py/actions/)
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH-libs/tuft.py.svg)](https://libraries.io/github/KOLANICH-libs/tuft.py)

This is a small high-level library for creating [The Update Framework](https://github.com/theupdateframework/specification) repositories.

This library is **insecure**:

* it has never been audited and/or even throughly tested.
* repo validation when it is created is not implemented. If a repo invalid or tampered, it will still be signed by your signature.
