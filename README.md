# 🛡️ BeeScan

**BeeScan** is a modular platform for comprehensive IT infrastructure security auditing. It supports integration of external tools as plugins, automated result collection and structuring, multi-format report generation, and flexible centralized configuration. The architecture enables analysis of networks, web applications, DNS, and APIs, and is scalable for any DevSecOps, penetration testing, or monitoring tasks.

## Key Features

- **Plugin support** — 5 tools integrated.  
- **Plug-and-Play architecture** — each tool is a separate parser module.  
- **PostgreSQL output** and report rendering from the database.  
- **Tool profiles** — choose scan level per tool.  
- **Report generation**: TERMINAL, HTML, PDF.  
- **Docker isolation** — separate containers for core and database.  
- **Logging** — separate logs for host and container.  
- **Multilingual support** — language switching via `config.json` and new languages via `lang.json`.

## Use Cases

- **Pentests and penetration testing**  
- **Infrastructure and web service audits**  
- **Government and corporate network security**  
- **DevSecOps and CI/CD**

## Tech Stack

- **Python** — main development language  
- **PostgreSQL** — database  
- **Docker** — environment containerization  
- **Jinja2** — report templates  
- **Rich** — terminal tables  
- **WeasyPrint** — PDF generation

### Integrated Tools

| Tool    | Description                                                                 | Version                  |
|---------|-----------------------------------------------------------------------------|--------------------------|
| `nmap`  | Powerful network scanner for port discovery and service/version detection. | ![v](https://img.shields.io/badge/nmap-stable-blue) |
| `nikto` | Web server scanner for detecting misconfigurations and vulnerabilities.    | ![v](https://img.shields.io/badge/nikto-2.5.0-blue) |
| `dig`   | Command-line DNS lookup utility for querying name servers.                 | ![v](https://img.shields.io/badge/dig-bind9-blue)   |
| `nuclei`| Fast vulnerability scanner based on YAML templates.                        | ![v](https://img.shields.io/badge/nuclei-v3.4.3-blue) |

## Architecture

### System Components

1. **Plugins (`plugins/*.py`)** — wrapper modules for CLI tools (e.g., `nmap`, `nikto`). Each plugin implements the following functions:
   - `scan()` — runs the scanner and saves the path to the result file (`.xml`, `.json`);
   - `parse()` — parses the results;
   - `merge_entries()` — merges data by IP and Domain into `source: "Both"`;
   - `get_column_order()` and `get_wide_fields()` — configure table column order and visual formatting.
2. **Runner (`plugin_runner.py`)** — launches plugins and saves the paths to their results in a temporary JSON (`/tmp/temp_files_*.json`) without storing the actual file content.
3. **Collector (`collector.py`)** — loads file paths, calls `parse()` / `merge_entries()`, filters out uninformative entries, and stores the result in the `results` table.
4. **Database (PostgreSQL)** — centralized repository for all results, all data is converted to a single schema and stored in tables.
5. **Report Generator (`report_generator.py`)** — retrieves data from the database, groups it by category, and visualizes it as:
   - terminal report,
   - HTML,
   - PDF.
6. **Configuration Module (`config/config.json`)** — defines scanning targets (`target_ip`, `target_domain`), active plugins, scan levels, report formats, theme (`light` / `dark`), and behavior (`open_report`, `clear_db`, etc.).
7. **Startup Wrapper (`start.py`)** — single entry point that orchestrates Docker environment setup, database launch, scanner execution, data collection, and report generation with progress indicators.
8. **Docker Environment** — isolated and fully self-contained environment:
   - `beescan_base` — container with all scanners and logic,
   - `postgres` — separate container for the database,
   - `beescan_network` — bridge network connecting the components.

### Project Structure

```
beescan/
├── config/                    # Configuration files
│   ├── plugins/
│   │   ├── nikto.json         # Profile and levels for Nikto
│   │   └── nmap.json          # Profile and levels for Nmap
│   ├── config.json            # Main BeeScan configuration (targets, plugins, etc.)
│   └── start.py               # Entry point, CLI launcher for the system
├── core/                      # Core system
│   ├── collector.py           # Parser and integrator into the database
│   ├── logger_container.py    # Container-level logger (core)
│   ├── logger_host.py         # Host-level logger (core)
│   ├── logger_plugin.py       # Logger for individual plugins
│   ├── orchestrator.py        # Manages dependencies and launch order
│   ├── plugin_runner.py       # Launches all plugins and records temp files
│   ├── registry.py            # Works with the registry table (target queue)
│   ├── report_generator.py    # Report generator (terminal, HTML, PDF)
│   └── severity.py            # Severity levels and classification
├── db/                        # Database configuration
│   ├── compose.yaml           # Docker Compose for PostgreSQL
│   ├── Dockerfile             # Dockerfile (optional)
│   ├── init.sql               # Database schema initialization
│   └── populate_db.py         # Script to insert test data
├── docker/                    # Docker setup
│   ├── Dockerfile.base        # Dockerfile for beescan-base (scanners, Python)
│   └── install_plugins.py     # Script to install CLI tools in the container
├── logs/                      # Logging
│   ├── container.log          # Container log
│   ├── host.log               # Host log
│   ├── nikto.log              # Nikto plugin log
│   └── nmap.log               # Nmap plugin log
├── plugins/                   # Scanner plugins/parsers
│   ├── dig.py                 # Plugin for dig
│   ├── nikto.py               # Plugin for Nikto
│   ├── nmap.py                # Plugin for Nmap
│   └── nuclei.py              # Plugin for nuclei
├── reports/                   # Generated reports
│   ├── *.html
│   ├── *.json
│   └── *.pdf
├── templates/                 # Jinja2 report templates
│   ├── css/                   # Stylesheets
│   ├── plugins/               # Plugin-specific HTML subtemplates
│   │   ├── nmap.html.j2
│   └── report.html.j2         # Main HTML template
├── requirements.txt           # Python requirements
├── start.sh                   # Bash launcher for the full system
└── version.txt                # Release version
```
## Pipeplan: How It Works

### System Startup

1. The system is started via `start.sh`. The bash wrapper checks the environment, launches `start.py`, and runs the orchestration pipeline.
2. Docker and the `beescan_network` network are checked/created.
3. Containers are started:
   * PostgreSQL (`beescan_postgres`)
   * beescan-base (core logic + scanners)
4. `plugin_runner.py` is launched for asynchronous scanning of targets.
5. Paths to scan results are saved in a temporary file `/tmp/temp_files_*.json`.
6. `collector.py` is launched to parse, normalize, filter, and write results to the DB (strictly to the snapshot schema).
7. Reports are generated: `terminal`, `html`, `pdf` — all based on DB data via `report_generator.py`.

### Plugin Workflow (`plugin_runner.py`)
1. Plugin activity is determined via `config.json`.
2. The `scan()` function is called asynchronously:
   * Launches the scanner (e.g., nmap) with the required profile/arguments.
   * Saves results (XML, JSON, STDOUT) to temporary files.
3. Temporary files are not read directly; only their paths are saved to a temporary JSON.
4. Only the collector operates with the results from this point.

### Data Collection (`collector.py`)

1. The collector connects to the database.
2. Loads the plugin parser from `plugins/*.py`.
3. Processes all temporary files (`temp_files_*.json`):
   * Calls `parse()` to parse results,
   * Calls `merge_entries()` to unify duplicates,
   * Filters out non-informative records.
4. All valid entries are distributed across tables:
   * **hosts** — unique IPs/FQDNs and OS info.
   * **services** — unique services (port, protocol, CPE, product, etc.).
   * **vuln** — result for each service finding (always includes severity, description, references, etc.).
   * **evidence** — if needed, stores original logs (e.g., XML or stdout).
   * **registry** — dynamic index of targets for passive/follow-up plugins.

### Unified Data Schema

* Any plugin result is always mapped to universal fields: `host`, `service`, `port`, `protocol`, `severity`, `description`, `evidence`, `references`, `source`.
* If a plugin returns something specific, it goes into `meta`, `evidence`, or an extended description field.
* Raw data (`evidence`) is optional: e.g., for nmap, original XML/STDOUT can be saved in evidence; for nuclei — the JSON report, etc.

### Report Generation (`report_generator.py`)

1. Fresh data is extracted from the snapshot: tables `hosts`, `services`, `vuln`, `evidence`, `registry`.
2. Data is automatically grouped by category and active plugins according to `config.json` (`category` for each plugin).
3. For each plugin, the following are queried:
   * column order (`get_column_order()`)
   * wide fields (`get_wide_fields()`)
   * view (`get_view_rows()`)
4. Generates reports in the selected formats:
   * **Terminal report** (rich tables, full plugin output)
   * **HTML report** (via the universal Jinja2 template `report.html.j2`, adapting to each plugin's structure)
   * **PDF report** (generated from HTML via WeasyPrint)
5. Theme selection is supported (`"light"` or `"dark"`).
6. All reports are built strictly from the current state of the DB — no intermediate JSON/logs are used.

### Nmap Example

1. The `nmap` module is enabled, a scan profile is set (`easy` / `middle` / `hard`).
2. For each target (ip/domain/network), nmap is run with the respective profile (arguments, ports, scripts).
3. Each result is saved separately, then collected, parsed, and normalized via plugin functions (`parse()`, `merge_entries()`, `get_view_rows()`).
4. All data is strictly stored in the snapshot:
   * services (`services`)
   * hosts (`hosts`)
   * individual findings (`vuln`)
   * if needed, raw XML (`evidence`)
5. All results are visible in the reports:
   * **Terminal** — aggregated output for all services and severity levels.
   * **HTML/PDF** — tabular, with sorting, filtering by categories/plugins, scan duration, and theme support.

## Installation and Launch

### Launching the Project

```bash
git clone https://github.com/beesyst/beescan.git
cd beescan
bash start.sh
```

You will be prompted to select a language during setup.

## Configuration

All parameters are set in `config.json`:

| Parameter            | Default value            | What `true`/value does                                      | What `false`/other value does                  |
|----------------------|-------------------------|-------------------------------------------------------------|------------------------------------------------|
| `target_ip`          | `"1.1.1.1"`             | Scans the specified IP address                              | —                                              |
| `target_domain`      | `""`                    | Scans the specified domain                                  | —                                              |
| `target_network`     | `""`                    | Scans the specified network range (e.g., `1.1.1.0/24`)      | —                                              |
| `target_api`         | `""`                    | For integration with external API (optional)                | —                                              |
| `report_formats`     | `["terminal", "html"]`  | Generates the selected report formats                       | —                                              |
| `open_report`        | `true`                  | Automatically opens HTML/PDF report in browser              | Does not open reports in browser               |
| `clear_logs`         | `true`                  | Clears logs before each run                                 | Logs are accumulated                           |
| `clear_reports`      | `true`                  | Deletes old reports before each run                         | Old reports are preserved                      |
| `clear_db`           | `true`                  | Clears all database tables before scanning                  | Old data in the database is preserved          |
| `report_theme`       | `"dark"`                | Uses dark theme for HTML and PDF reports                    | `"light"` — uses light report theme            |
| `plugins`            | see section below       | List of active plugins and their parameters                 | —                                              |

## To-Do

<!--KANBAN_START-->
| Todo (5) | In Progress (2) | Done (26) |
| --- | --- | --- |
| PDF reports | Summary of vulnerabilities by severity | Nikto: Auto-select web ports from Nmap scan results |
| Proxy integration (Tor/Chain) | Normalize database structure and remove legacy `results` table | Dynamic plugin chaining: automatic orchestration based on scan dependencies |
| Integrate dig | &nbsp; | Implement target registry for cross-plugin orchestration |
| Integrate nuclei | &nbsp; | Strict report and plugin order in output (categories + plugins) |
| Multi-language support (RU/EN) | &nbsp; | Vulnerability severity classification |
| &nbsp; | &nbsp; | Add network target support to nmap plugin configuration |
| &nbsp; | &nbsp; | Add require and enabled fields to Nmap |
| &nbsp; | &nbsp; | Auto-update Kanban board in README from GitHub Projects |
| &nbsp; | &nbsp; | Expansion of scan complexity levels |
| &nbsp; | &nbsp; | Scanner update check before run |

<!--KANBAN_END-->

## Donate

- **USDT (TRC20)**/**USDC (TRC20)**: `TUQj3sguQjmKFJEMotyb3kERVgnfvhzG7o`
- **SOL (Solana)**: `6VA9oJbkszteTZJbH6mmLioKTSq4r4E3N1bsoPaxQgr4`
- **XRP (XRP)**: `rDkEZehHFqSjiGdBHsseR64fCcRXuJbgfr`

---

**🛡 Licensed for non-commercial use only. See [LICENSE](LICENSE) for details.**

