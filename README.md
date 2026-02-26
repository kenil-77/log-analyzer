# 🔍 Log Analyzer — SSH Brute Force Detection Tool

A professional security tool that analyzes Linux SSH log files, detects brute force attacks, and generates detailed reports in multiple formats.

Built with Python — designed to look and work like a real security analyst tool.

---

## 🚀 Features

- Parses real Linux SSH auth.log files
- Detects brute force attacks by grouping failed logins per IP
- Identifies which usernames are being targeted most
- Displays beautiful colored terminal output using Rich
- Exports results to CSV, HTML, and JSON formats
- Supports command line arguments for flexibility
- Handles large log files efficiently by reading line by line

---

## 📁 Project Structure
```
log-analyzer/
├── main.py                    # Entry point — connects everything
├── generate_test_logs.py      # Generates fake logs for testing
├── parsers/
│   ├── __init__.py
│   └── ssh_parser.py          # Reads and parses auth.log with regex
├── analyzers/
│   ├── __init__.py
│   └── brute_force.py         # Detects suspicious IPs using pandas
├── reporters/
│   ├── __init__.py
│   ├── report.py              # Beautiful terminal output using Rich
│   └── export.py              # CSV and HTML export
├── sample_logs/
│   └── auth.log               # Sample or real log file
├── reports/                   # Generated report files land here
└── requirements.txt
```

---

## ⚙️ Installation

**1. Clone the repository:**
```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```

**2. Create and activate virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## 🖥️ Usage

**Basic usage:**
```bash
python main.py --log sample_logs/auth.log --threshold 5
```

**With export to JSON:**
```bash
python main.py --log sample_logs/auth.log --threshold 5 --export
```

**Generate fake test logs:**
```bash
python generate_test_logs.py
python main.py --log sample_logs/auth.log --threshold 5 --export
```

**On a real Linux server:**
```bash
sudo cp /var/log/auth.log sample_logs/auth.log
sudo chmod 644 sample_logs/auth.log
python main.py --log sample_logs/auth.log --threshold 10 --export
```

**See all options:**
```bash
python main.py --help
```

---

## 🔧 Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--log` | Yes | None | Path to the log file to analyze |
| `--threshold` | No | 5 | Failed attempts before flagging an IP |
| `--export` | No | False | Export findings to JSON file |

---

## 📊 Output Formats

| Format | Location | Use Case |
|--------|----------|----------|
| Terminal | Your screen | Quick analysis |
| CSV | `reports/ssh_report_*.csv` | Open in Excel or Google Sheets |
| HTML | `reports/ssh_report_*.html` | Open in browser, share with team |
| JSON | `report.json` | Feed into other tools or dashboards |

---

## 🛠️ How It Works

**1. Parsing** — `ssh_parser.py` reads the log file line by line and uses regex to extract timestamp, username, IP address, and port number

**2. Analysis** — `brute_force.py` uses pandas to group failed logins by IP, count attempts, flag IPs above threshold, and find targeted usernames

**3. Reporting** — `report.py` uses Rich library to display a summary panel, color-coded brute force table, and most targeted usernames

**4. Export** — `export.py` saves results to CSV, HTML, and JSON formats

---

## 📚 Libraries Used

| Library | Purpose |
|---------|---------|
| `rich` | Beautiful terminal output — tables, panels, colors |
| `pandas` | Data analysis — grouping, counting, filtering |
| `requests` | HTTP requests for future GeoIP lookup |
| `tabulate` | Alternative table formatting |
| `colorama` | Cross-platform terminal colors |

---

## 👨‍💻 Author

Built by Kenil as a cybersecurity portfolio project.
Designed to demonstrate real security tooling skills using Python.

---

## 📄 License

MIT License — free to use, modify, and distribute.
