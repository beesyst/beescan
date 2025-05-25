# 🛡️ BeeScan

**BeeScan** is a modular platform for comprehensive IT infrastructure security auditing. It supports integration of external tools as plugins, automated result collection and structuring, multi-format report generation, and flexible centralized configuration. The architecture enables analysis of networks, web applications, DNS, and APIs, and is scalable for any DevSecOps, penetration testing, or monitoring tasks.

## ⚙️ Key Features

- **Plugin support** — 5 tools integrated.  
- **Plug-and-Play architecture** — each tool is a separate parser module.  
- **PostgreSQL output** and report rendering from the database.  
- **Tool profiles** — choose scan level per tool.  
- **Report generation**: TERMINAL, HTML, PDF.  
- **Docker isolation** — separate containers for core and database.  
- **Logging** — separate logs for host and container.  
- **Multilingual support** — language switching via `config.json` and new languages via `lang.json`.

## 🌍 Use Cases

- **Pentests and penetration testing**  
- **Infrastructure and web service audits**  
- **Government and corporate network security**  
- **DevSecOps and CI/CD**

## 🛠️ Tech Stack

- **Python** — main development language  
- **PostgreSQL** — database  
- **Docker** — environment containerization  
- **Jinja2** — report templates  
- **Rich** — terminal tables  
- **WeasyPrint** — PDF generation

### 🔌 Integrated Tools

| Tool    | Description                                                                 | Version                  |
|---------|-----------------------------------------------------------------------------|--------------------------|
| `nmap`  | Powerful network scanner for port discovery and service/version detection. | ![v](https://img.shields.io/badge/nmap-stable-blue) |
| `nikto` | Web server scanner for detecting misconfigurations and vulnerabilities.    | ![v](https://img.shields.io/badge/nikto-2.5.0-blue) |
| `dig`   | Command-line DNS lookup utility for querying name servers.                 | ![v](https://img.shields.io/badge/dig-bind9-blue)   |
| `nuclei`| Fast vulnerability scanner based on YAML templates.                        | ![v](https://img.shields.io/badge/nuclei-v3.4.3-blue) |

## 🖧 Architecture

### System Components

1. **Plugins (`plugins/*.py`)** — wrapper modules for CLI tools (e.g., `nmap`, `nikto`). Each plugin implements the following functions:
   - `scan()` — runs the scanner and saves the path to the result file (`.xml`, `.json`);
   - `parse()` — parses the results;
   - `merge_entries()` — merges data by IP and Domain into `source: "Both"`;
   - `get_column_order()` and `get_wide_fields()` — configure table column order and visual formatting.
2. **Runner (`plugin_runner.py`)** — launches plugins and saves the paths to their results in a temporary JSON (`/tmp/temp_files_*.json`) without storing the actual file content.
3. **Collector (`collector.py`)** — loads file paths, calls `parse()` / `merge_entries()`, filters out uninformative entries, and stores the result in the `results` table.
4. **Database (PostgreSQL)** — centralized storage for all results; all plugins write to a single `results` table with a `plugin` field for identification.
5. **Report Generator (`report_generator.py`)** — retrieves data from the database, groups it by category, and visualizes it as:
   - terminal report (using rich),
   - HTML (Jinja2 + CSS),
   - PDF (via WeasyPrint).
6. **Configuration Module (`config/config.json`)** — defines scanning targets (`target_ip`, `target_domain`), active plugins, scan levels, report formats, theme (`light` / `dark`), and behavior (`open_report`, `clear_db`, etc.).
7. **Startup Wrapper (`start.py`)** — single entry point that orchestrates Docker environment setup, database launch, scanner execution, data collection, and report generation with progress indicators.
8. **Docker Environment** — isolated and fully self-contained environment:
   - `beescan_base` — container with all scanners and logic,
   - `postgres` — separate container for the database,
   - `beescan_network` — bridge network connecting the components.

### Project Structure

```
beescan/
├── config/                  # Configuration
│   ├── config.json          # Main config file
│   └── start.py             # Main Python launch script
├── core/                    # Core system
│   ├── collector.py         # Parses results to DB
│   ├── logger_container.py  # Logs from inside container
│   ├── logger_host.py       # Logs from host
│   ├── plugin_runner.py     # Runs active plugins
│   └── report_generator.py  # Builds reports from DB
├── db/                      # PostgreSQL setup
│   ├── compose.yaml         # Docker Compose config
│   ├── Dockerfile           # PostgreSQL Dockerfile (optional)
│   ├── init.sql             # DB initialization
│   └── populate_db.py       # Manual test data insert
├── docker/                  # Docker environment
│   ├── Dockerfile.base      # Base container Dockerfile
│   └── install_plugins.py   # CLI tool installer
├── logs/                    # Logs
│   ├── container.log        # Container log
│   └── host.log             # Host log
├── plugins/                 # Scanner parsers
│   ├── nmap.py              # Nmap parser
│   └── nikto.py             # Nikto parser
├── reports/                 # Generated HTML/PDF reports
├── templates/               # Jinja2 report templates
│   ├── css/                 # CSS files
│   └── report.html.j2       # HTML report template
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── start.sh                 # Bash autostart script
```

## ⚙️ Pipeplan: How it Works

### System Launch

1. The system starts via `start.sh`.
2. Checks for Docker and the `beescan_network`.
3. Launches the PostgreSQL container (if not already running).
4. Builds the `beescan-base` image (if not built yet).
5. Starts the `beescan_base` container with mounted folders.
6. Runs `plugin_runner.py` to scan targets.
7. Saves result paths to a temporary JSON file.
8. Launches `collector.py` to process results and write to the database.
9. Generates reports: `terminal`, `html`, `pdf`.

### Plugin Operation

1. `plugin_runner.py` reads `config.json` and detects active plugins.
2. Triggers the `scan()` function in each plugin (`plugins/*.py`).
3. Saves result paths (`XML`/`JSON`) into a temporary file.
4. Calls the `parse()` function for each plugin to extract data.

### Data Collection (`collector.py`)

1. The collector connects to the database.
2. Clears the `results` table if `"clear_db": true` is enabled.
3. Loads the plugin parser from `plugins/*.py`.
4. Processes all temporary files (`temp_files_*.json`).
5. Calls `parse()` and `merge_entries()`.
6. Filters out empty or non-informative entries.
7. Writes structured data into the unified `results` table.

### Report Generation (`report_generator.py`)

1. Fetches data from the `results` table.
2. Automatically detects categories (`Network Security`, `Application Security`, etc.).
3. For each plugin, loads column order (`get_column_order()`) and wide fields (`get_wide_fields()`).
4. Generates:
   - Terminal report (`rich` tables),
   - HTML report (via `Jinja2` template `report.html.j2`),
   - PDF report (based on HTML via `WeasyPrint`).
5. The HTML report opens automatically in the browser if `"open_report": true` in `config.json`.
6. Supports theme selection: `"light"` or `"dark"`.

### Nmap Example

1. The `config.json` specifies the `nmap` module with a difficulty level (e.g., `middle`).
2. Nmap is launched with arguments for that level (`-T4 -sS -sV -Pn --open`, etc.).
3. Scans for both IP and Domain are saved separately.
4. The `nmap.py` plugin:
   - Parses the XML output,
   - Merges IP/Domain results using `merge_entries()`,
   - Passes the data to the collector.
5. All records are added to the `results` table.
6. `report_generator.py` displays the results in terminal, HTML, and PDF with proper column ordering.

## ▶️ Installation and Launch

### Launching the Project

```bash
git clone https://github.com/beesyst/beescan.git
cd beescan
bash start.sh
```

You will be prompted to select a language during setup.

## 🔧 Configuration

All parameters are set in `config.json`:

| Parameter        | Default              | `true` behavior                                                       | `false` behavior                                |
|------------------|----------------------|------------------------------------------------------------------------|--------------------------------------------------|
| `target`         | `"1.1.1.1"`           | Scans specified IP or domain                                           | —                                                |
| `report_formats` | `["terminal", "html"]` | Generates formats: `terminal`, `html`, `pdf`                          | —                                                |
| `open_report`    | `true`                | Auto-opens HTML/PDF in browser                                         | Doesn't open automatically                       |
| `clear_logs`     | `true`                | Clears `host.log` and `container.log` on launch                        | Logs persist and accumulate                      |
| `clear_reports`  | `true`                | Removes old reports from `reports/`                                    | Keeps old reports                                |
| `clear_db` | `true`                | Empties the database before scan                                       | Keeps previous results in DB                     |
| `report_theme`   | `"dark"`              | Uses dark mode in HTML/PDF reports                                     | `"light"` — light theme                         |

## 🗺️ To-Do

<!--KANBAN_START-->
| Todo (5) | In Progress (3) | Done (22) |
| --- | --- | --- |
| PDF reports | Summary of vulnerabilities by severity | Vulnerability severity classification |
| Proxy integration (Tor/Chain) | Nikto: Auto-select web ports from Nmap scan results | Add network target support to nmap plugin configuration |
| Integrate dig | Dynamic plugin chaining: automatic orchestration based on scan dependencies | Add require and enabled fields to Nmap |
| Integrate nuclei | &nbsp; | Auto-update Kanban board in README from GitHub Projects |
| Multi-language support (RU/EN) | &nbsp; | Expansion of scan complexity levels |
| &nbsp; | &nbsp; | Scanner update check before run |
| &nbsp; | &nbsp; | Reports from PostgreSQL (HTML, Terminal) |
| &nbsp; | &nbsp; | Asynchronous plugin execution |
| &nbsp; | &nbsp; | Flexible configuration via config.json |
| &nbsp; | &nbsp; | Log and report cleanup via config flags |

<!--KANBAN_END-->

## 💰 Donate

- **USDT (TRC20)**/**USDC (TRC20)**: `TUQj3sguQjmKFJEMotyb3kERVgnfvhzG7o`
- **SOL (Solana)**: `6VA9oJbkszteTZJbH6mmLioKTSq4r4E3N1bsoPaxQgr4`
- **XRP (XRP)**: `rDkEZehHFqSjiGdBHsseR64fCcRXuJbgfr`

---

**🛡 Licensed for non-commercial use only. See [LICENSE](LICENSE) for details.**

