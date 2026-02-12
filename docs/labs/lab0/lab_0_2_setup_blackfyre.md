# 🔹 Lab 0.2 — Install Blackfyre (Editable)

> 🔧 **This is a tool-running lab.** You will install the Blackfyre Python library in editable mode and validate it imports.
>
> ⚠️ **This lab requires executing commands.**

---

## Overview

- **Goal:** Install Blackfyre so later labs can parse and work with binary artifacts.
- **Inputs:** A working Python 3.12+ venv (from Lab 0.1).
- **Outputs:** Blackfyre installed in editable mode (`pip install -e .`) and verified via a real example script.

> ⚠️ **Architecture note:** Use an **x86_64** machine/environment for this workshop. Blackfyre depends on `pyvex` (from the angr ecosystem), and on some ARM environments `pyvex` installation/build can be problematic.

---

## 🎯 Why Blackfyre?

Reverse engineering tools (Ghidra, IDA, Binary Ninja, etc.) all expose rich program structure, but they store that structure in tool-specific internal formats. That makes it hard to build reusable, automation-friendly pipelines.

**Blackfyre** solves this by providing a **standardized, disassembler-agnostic representation** of binaries called the **Binary Context Container (BCC)**. A BCC (stored as a `.bcc` file) captures the key program facts we care about in a structured way:
- Binary metadata (name, SHA256, file type, architecture)
- Functions and basic blocks
- Call relationships and other cross-references
- Imports/exports and strings
- Optional decompiler output

### Protocol Buffers (protobuf)

Blackfyre stores BCCs using **Protocol Buffers (protobuf)**.

**Protobuf** is a compact, language-neutral way to define structured data (via a schema) and serialize it efficiently. In practice, protobuf gives us:
- A stable, versionable schema for binary metadata
- Fast parsing in Python (and other languages if needed)
- Portable `.bcc` artifacts we can reuse across tools and pipelines

In this workshop, Blackfyre is how we get the **ground-truth structure** that binql-ultra-lite uses to build graphs.

Once those entities and relationships are extracted, binql-ultra-lite can load them into Neo4j as nodes and edges. That’s what makes “system-level questions” possible ("what calls memcpy?", "what paths reach a risky API?", "what binaries share the same import-driven behavior?") — and it’s also what lets an LLM generate queries against a concrete schema rather than guessing.

For more detail on what Blackfyre extracts and how BCCs are structured, see the Blackfyre README:
- https://github.com/jonescyber-ai/Blackfyre/blob/main/README.md

---

## 🎯 What You Need To Do

### Step 1: Clone the Blackfyre repository

From the `binql-ultra-lite-workshop/` repo root:

#### Linux/macOS

```bash
git clone https://github.com/jonescyber-ai/Blackfyre.git
```

#### Windows

```powershell
git clone https://github.com/jonescyber-ai/Blackfyre.git
```

This creates a `Blackfyre/` folder inside the repo root.

---

### Step 2: Install the Python library (editable)

#### Linux/macOS

From your `binql-ultra-lite-workshop/` repo root:

```bash
# Activate the workshop venv
source venv/bin/activate

# Go to the Blackfyre Python package
cd Blackfyre/src/python

# Install Blackfyre into the active venv
pip install -e .
```

> ℹ️ **How to verify activation:** Your prompt should show `(venv)` at the beginning. You can also run `echo $VIRTUAL_ENV` — if it prints a path, the venv is active.

#### Windows (PowerShell)

From your `binql-ultra-lite-workshop\` repo root:

> ⚠️ **PowerShell execution policy:** Activating a venv runs a `.ps1` script. If you get an error about running scripts being disabled when activating the venv, run this first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

```powershell
# Activate the workshop venv
.\venv\Scripts\Activate.ps1

# Go to the Blackfyre Python package
cd Blackfyre\src\python

# Install Blackfyre into the active venv
pip install -e .
```

> ℹ️ **How to verify activation:** Your prompt should show `(venv)` at the beginning, e.g. `(venv) PS C:\...>`. You can also run `$env:VIRTUAL_ENV` — if it prints a path, the venv is active.

> ℹ️ The key requirement is: **activate the same `venv/` you’ll use for the workshop, then run `pip install -e .` from `Blackfyre/src/python`.**

---

### Step 3: Validate Blackfyre imports

#### Linux/macOS

From `binql-ultra-lite-workshop/` (with venv active):

```bash
python -c "import blackfyre; print('Blackfyre import: OK')"
```

#### Windows

From `binql-ultra-lite-workshop\` (with venv active):

```powershell
python -c "import blackfyre; print('Blackfyre import: OK')"
```

---

### Step 4: Run the Blackfyre metadata example (sanity check)

#### Linux/macOS

From `binql-ultra-lite-workshop/` (with venv active):

```bash
python Blackfyre/examples/python/example_displaying_binary_metadata.py
```

#### Windows (PowerShell)

From `binql-ultra-lite-workshop\` (with venv active):

```powershell
python .\Blackfyre\examples\python\example_displaying_binary_metadata.py
```

**What this script does:**
- Loads a known-good test `.bcc` file shipped with Blackfyre
- Parses it into a `BinaryContext`
- Prints high-level binary metadata (name, SHA256, architecture/file type) and summary counts
- Prints a short preview of function-level metadata so you can confirm the container was parsed correctly

**What success looks like:**
- The script runs without exceptions
- You see printed metadata including `Binary Name`, `Binary SHA256`, and function summaries

---

## ✅ Success Criteria

You’re done when:
- [ ] `pip install -e .` succeeds in `Blackfyre/src/python`
- [ ] `python -c "import blackfyre"` works
- [ ] `python Blackfyre/examples/python/example_displaying_binary_metadata.py` runs without exceptions

---

## Summary

Blackfyre is now installed and validated. Continue to Lab 0.3 (lab_0_3_setup_neo4j.md).

---

## 📚 Additional Reading

Blackfyre README:
- https://github.com/jonescyber-ai/Blackfyre/blob/main/README.md

