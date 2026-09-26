# Contributing to RECON-WIRE

Thank you for your interest in contributing to **RECON-WIRE**! We welcome bug reports, feature requests, performance optimizations, and new reconnaissance modules from security researchers and developers worldwide.

---

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/recon-wire.git
   cd recon-wire
   ```

2. **Create a Python virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies and editable package:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```

4. **Verify local installation:**
   ```bash
   recon-wire --help
   ```

---

## 🧩 Adding a New Reconnaissance Module

RECON-WIRE is designed with a decentralized, decoupled architecture:
1. **Module placement:** Put all logic in `modules/<feature>.py` (never use `_module.py` suffix).
2. **State compliance:**
   - Modules must **never import each other**.
   - Read and write state only via the single `AppState` instance passed into `__init__(self, state: AppState)`.
   - Update `self.state.module_statuses[NAME]` with progress (0–100) and status (`RUNNING`, `DONE`, `ERROR`).
3. **Findings pipeline:** Use `push_finding(self.state.findings_queue, ...)` to submit security issues.
4. **Integration steps:**
   - Expose your class in `modules/__init__.py`.
   - Add module flags to `ScanConfig` and result lists to `AppState` in `app/state.py`.
   - Add `--no-<module>` toggle in `app/cli.py`.
   - Dispatch async task in `app/core.py`.
   - Add export serialization in `app/export.py` for JSON, Markdown, and Text.

---

## 🧪 Testing & Code Quality

Before submitting a pull request, ensure all tests pass:

```bash
# Run test suite
pytest -v tests/

# Run linter
ruff check .

# Run type checker
mypy app/ modules/
```

---

## 📬 Pull Request Guidelines

1. Create a descriptive feature branch (`git checkout -b feature/awesome-vector`).
2. Commit your changes with meaningful commit messages.
3. Push to your branch and open a Pull Request against `main`.
4. Ensure your PR description details the motivation, changes made, and test commands used.
