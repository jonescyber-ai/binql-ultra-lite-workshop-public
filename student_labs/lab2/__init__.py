"""
Student Labs - Lab 2: NL2GQL (Natural Language to Graph Query Language).

This package contains student implementations for Lab 2, which covers:
- Lab 2.1: Schema Export - Extract schema metadata using APOC procedures
- Lab 2.2: Schema Enrichment - Add sample values to schema for better LLM context
- Lab 2.3: Prompt Builder - Build LLM prompts with schema context
- Lab 2.4: Response Parser - Extract Cypher from LLM responses
- Lab 2.5: Query Executor - Execute queries with automatic retry

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.nl2gql --query "Find all binaries with more than 100 functions"

Reference: docs/labs/lab2/lab_2_0_overview.md
"""
