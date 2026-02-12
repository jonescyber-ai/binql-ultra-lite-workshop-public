# 🔹 Lab 0.1 — Python + IDE Setup (Python 3.12+)

> 🔧 **This is a tool-running lab.** You will install/select Python 3.12+, create a virtual environment, and configure your IDE to use it.
>
> ⚠️ **This lab requires executing commands.**

---

## Overview

- **Goal:** Ensure you have Python 3.12+ and a working virtual environment for this repo.
- **Inputs:** Python 3.x installed locally.
- **Outputs:** A `venv/` created with Python 3.12+, plus workshop dependencies installed.

---

## 🎯 What You Need To Do

### Step 1: Clone the workshop repository

#### Linux/macOS

```bash
git clone https://github.com/jonescyber-ai/binql-ultra-lite-workshop.git
cd binql-ultra-lite-workshop
```

> ℹ️ If the folder name on disk is different (for example, you cloned into a different directory name), just `cd` into the folder that was created by `git clone`.

#### Windows (PowerShell)

```powershell
git clone https://github.com/jonescyber-ai/binql-ultra-lite-workshop.git
cd binql-ultra-lite-workshop
```

> ℹ️ If the folder name on disk is different, just `cd` into the folder that was created by `git clone`.

---

## Linux/macOS Setup

### Step 2 (Linux/macOS): Confirm whether Python 3.12 is available

```bash
python3 --version
python3.12 --version
```

If `python3.12` works and is 3.12+, continue.

### Step 3 (Linux/macOS): Install Python 3.12 (if needed)

Ubuntu/Debian-like:

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
python3.12 --version
```

### Step 4 (Linux/macOS): Create and activate a venv using Python 3.12

```bash
python3.12 -m venv venv
source venv/bin/activate
python --version
python -m pip install --upgrade pip
```

> ℹ️ **How to verify activation:** If the venv is active, your prompt will show `(venv)` at the beginning. You can also run `echo $VIRTUAL_ENV` — if it prints a path, the venv is active.

### Step 5 (Linux/macOS): Install workshop Python dependencies

```bash
pip install -r requirements.txt
```

---

## Windows Setup

### Step 2 (Windows): Confirm whether Python 3.12 is available

```powershell
py -3.12 --version
```

### Step 3 (Windows): Install Python 3.12 (if needed)

1. Install Python 3.12+ from:
   - https://www.python.org/downloads/
2. During install, enable:
   - “Install launcher for all users” (recommended)
   - “Add python.exe to PATH” (optional; `py` is enough)

Re-validate:

```powershell
py -3.12 --version
```

### Step 4 (Windows): Create and activate a venv using Python 3.12

> ⚠️ **PowerShell execution policy:** Activating a venv runs a `.ps1` script. If you get an error about running scripts being disabled when activating the venv, run this first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

PowerShell:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
```

> ℹ️ **How to verify activation:** If the venv is active, your prompt will show `(venv)` at the beginning, e.g. `(venv) PS C:\...>`. You can also run `$env:VIRTUAL_ENV` — if it prints a path, the venv is active.

cmd.exe:

```bat
py -3.12 -m venv venv
venv\Scripts\activate.bat
python --version
python -m pip install --upgrade pip
```

### Step 5 (Windows): Install workshop Python dependencies

```powershell
pip install -r requirements.txt
```

---

## ✅ Success Criteria

You’re done when:
- [ ] With the venv activated, `python --version` shows **3.12+**
- [ ] `pip install -r requirements.txt` completes successfully

---

## Troubleshooting

### VS Code is using the wrong interpreter

In VS Code:
1. Open the Command Palette
2. Select **Python: Select Interpreter**
3. Choose the venv interpreter inside the workshop folder:
   - Linux/macOS: `<workshop-folder>/venv/bin/python`
   - Windows: `<workshop-folder>\\venv\\Scripts\\python.exe`
4. Open a new terminal in VS Code and verify:

```bash
python --version
```

### PyCharm is using the wrong interpreter

In PyCharm:
1. Settings → Project → Python Interpreter
2. Add Interpreter → Existing
3. Select the venv interpreter inside the workshop folder:
   - Linux/macOS: `<workshop-folder>/venv/bin/python`
   - Windows: `<workshop-folder>\\venv\\Scripts\\python.exe`

---

## Summary

Your Python environment is ready. Continue to Lab 0.2 (lab_0_2_setup_blackfyre.md).
