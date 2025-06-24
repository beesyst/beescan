# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0](https://github.com/beesyst/beescan/compare/v1.0.0...v1.1.0) (2025-06-24)


### Features

* **nmap:** migrate to core/severity.py for unified severity classification ([14f395a](https://github.com/beesyst/beescan/commit/14f395a0d1341931a9fe726dcc04836d5f6cd8d3))
* plugin templating and core refactor for plugin system (+MINOR) ([de014b6](https://github.com/beesyst/beescan/commit/de014b674581399c0ed5c4a76564ece707fdf832))


### Bug Fixes

* **orchestrator:** correct plugin execution order and dependency handling ([b111790](https://github.com/beesyst/beescan/commit/b111790d750c18931fb18befc86a5128acc62864))
* **report:** unify nmap details column in terminal and html reports ([59b5722](https://github.com/beesyst/beescan/commit/59b57225cd1bf8a02b559881eb95c6349ebfd18d))

## [Unreleased]

---

## [1.0.0] - 2024-05-13

### Added
- Initial release of BeeScan under version v1.0.0.
- Modular, extensible scanning platform for web and network security assessments.
- Plugin system with support for nmap, nikto, and dig.
- Integrated PostgreSQL database for centralized result storage.
- Report generation in Terminal, HTML, and PDF formats.
- Support for light and dark themes in HTML reports.
- Fully dockerized architecture with isolated scanning environments.
- Asynchronous plugin execution for performance.
- Modular configuration through `config.json`.
- Categorized results: Network Security, Application Security, DNS Health.
- Scan complexity levels: easy, middle, hard, extreme.

---

[Unreleased]: https://github.com/beesyst/beescan/compare/v1.0.0...HEAD  
[1.0.0]: https://github.com/beesyst/beescan/releases/tag/v1.0.0
