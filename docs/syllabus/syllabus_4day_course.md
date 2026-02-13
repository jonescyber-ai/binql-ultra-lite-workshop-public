# Automating Reverse Engineering with AI/ML, Graphs, and LLM Agents

## Brief Description

**TL;DR:** This course teaches automated reverse engineering (RE) for malware, firmware, and vulnerability analysis by shifting from isolated single-binary analysis to system-level reasoning. Students unify partial program facts recovered from disassembly into a graph that grounds LLMs and agents. Hands-on labs build a lightweight, BinQL-style analysis system with Neo4j and NL2GQL, which translates natural-language RE questions into graph queries, then apply embeddings, RAG, agent workflows (MCP/AutoGen), and fine-tuned LLaMA models for scalable RE automation.

This course teaches how to automate reverse engineering (RE) for malware, firmware, and vulnerability analysis using AI/ML, graphs, large language models (LLMs), and agents. Students begin with **Blackfyre**, an open-source framework that extracts binaries into a Protocol Buffers (protobuf) format for downstream analysis. Hands-on labs guide students in building a lightweight, BinQL-inspired graph analysis system using Blackfyre and Neo4j to support workflows such as malware family clustering, firmware analysis, and vulnerability tracing. A full open-source BinQL reference implementation will be released after the training cycle later this year.

Additional hands-on labs cover **NL2GQL**, which translates natural-language RE questions into graph queries so students can focus on analysis rather than query syntax, along with transformer-based embeddings, LLM techniques including **RAG** and **KnowledgeRAG**, and the **Model Context Protocol (MCP)**. The course culminates in applied labs on agentic workflows using fine-tuned **LLaMA** models and frameworks such as **AutoGen** for adaptive and automated reverse engineering.

---

## Full Description with Topics by Day

This course shifts reverse engineering from isolated single-binary analysis to system-level reasoning by unifying partial program facts recovered from disassembly into a single graph. That graph grounds LLMs and agents in explicit program structure, enabling scalable, evidence-driven automation.

Students begin with **Blackfyre**, an open-source framework developed for this course that extracts core program artifacts—**functions, basic blocks, control flow, calls, imports, and strings**—using both interactive and headless **Ghidra** workflows. This provides a repeatable foundation for prioritizing, comparing, and automating reverse engineering at scale.

Extracted artifacts are loaded into a **Neo4j-backed, BinQL-inspired program graph** that supports **behavioral binary similarity, malware clustering, firmware ecosystem analysis, and vulnerability triage**. **NL2GQL** translates natural-language analysis questions into executable graph queries, making the graph the interface between analyst intent, LLM reasoning, and agent actions. A full open-source reference implementation of **BinQL** will be released after the training cycle.

The second half of the course builds learning and automation directly on top of this graph. Graph-referenced artifacts are transformed into **embeddings** for similarity, clustering, and retrieval, guided by **Basic Block Rank (BBR)** to derive which code paths and artifacts matter most. Transformer models and LLMs extend this pipeline, culminating in **fine-tuning LLaMA-family models on A6000 GPUs** to improve NL2GQL accuracy for BinQL. The course concludes with **agent-based workflows** using **AutoGen** and **MCP** to automate tasks such as **patch impact analysis, N-day vulnerability triage, summarization, and YARA rule generation**—while remaining grounded in graph evidence.

**Prerequisites:** Students should have a solid foundation in reverse engineering and be comfortable with Python object-oriented development. Familiarity with basic ML concepts (e.g., vectors, supervised learning, precision/recall) is helpful but not required; these topics will be introduced and covered at the start of the course to bring all participants to a common baseline.

---

## Topics by Day

### Day 1: Introduction to Core Concepts and Techniques

Establishes a shared graph-based representation so reverse-engineering questions can be asked systematically rather than ad hoc.

- Automated RE overview and challenges of manual workflows, motivating representations that support reuse, scalability, and automation
- Fundamentals of binary analysis (IRs, pyvex/angr, Ghidra p-code) and Blackfyre: extracting functions, basic blocks, control flow, calls, imports, and strings into protobuf via interactive and headless workflows
- Graph-based program modeling from the start: loading artifacts into Neo4j and introducing BinQL and NL2GQL to ask structural questions such as reachability, input entry points, risky APIs, nearby evidence, and connecting paths
- **Labs:** Students extract artifacts with Blackfyre, load them into a program graph, and use BinQL and NL2GQL to answer core vulnerability and malware triage questions, establishing the representation used throughout the course.

### Day 2: Graph Workflows & Cross-Binary Analysis

Uses the program graph as an analysis engine for comparing behavior, structure, and risk across binaries.

- Cross-binary reasoning using shared structure, including malware clustering, firmware ecosystem analysis, and tracing reused or shared vulnerable code
- Refining NL2GQL queries to constrain results and inspect returned graph evidence rather than treating model output as authoritative
- Basic Block Rank (BBR): ranking execution-relevant basic blocks so importance propagates to referenced artifacts, revealing which imports, strings, and functions actually matter
- **Labs:** Students apply graph-based workflows for behavioral binary similarity using import call traces, graph-driven malware analysis for capability mapping and clustering, and graph-based vulnerability analysis to prioritize unsafe APIs, reachable exploit paths, reused code, and complex or rarely exercised regions.

### Day 3: Transformers & Neural Approaches for RE

Extends graph-based program analysis with neural representations that support downstream tasks such as similarity, function naming, and binary-level reasoning.

- Practical introduction to embeddings for RE, focusing on how graph-selected artifacts are encoded for comparison, grouping, and reuse across analyses
- Transformer concepts introduced through familiar RE artifacts, including tokenization of binary-derived sequences and handling long-context inputs
- Using Basic Block Rank (BBR) to select and weight program regions and referenced artifacts so embeddings emphasize execution-relevant behavior over noise
- **Labs:** Students generate embeddings from graph-selected artifacts, aggregate them using BBR, and apply them to downstream tasks including function name prediction, binary similarity, and cross-binary retrieval, writing the results back into the program graph

### Day 4: LLMs, Agents & Fine-Tuning

Integrates fine-tuned LLMs and agents to automate analysis while remaining grounded in graph evidence.

- Applying LLMs to RE tasks such as summarization, function labeling, vulnerability reporting, and rule drafting using structured program facts
- Fine-tuning LLaMA-family models on A6000 GPUs to improve NL2GQL accuracy for BinQL, increasing reliability and structural correctness of generated queries
- Agentic pipelines using AutoGen and MCP, where fine-tuned models, graph queries, and embeddings coordinate retrieval, reasoning, and verification
- **Labs:** Students fine-tune NL2GQL models and deploy agent workflows over the program graph for patch impact analysis, N-day vulnerability triage, graph-grounded summarization, firmware ecosystem analysis, and automated YARA rule generation.

---

## What’s New in This Course

This year’s course expands beyond earlier versions by introducing graph-driven workflows, advanced LLM methods, and agentic automation for reverse engineering:

- **BinQL with Neo4j:** Students gain exclusive early access to BinQL, which structures binaries as graphs of functions, basic blocks, imports, and strings, and enables cross-binary analysis through the GQL query standard.
- **Natural Language to GQL (NL2GQL):** Reverse engineering questions expressed in everyday RE language (e.g., “list binaries in this firmware image that call vulnerable function X”) are translated into precise graph queries.
- **Knowledge Graphs for Scaling Analysis:** Moving from single-binary workflows to ecosystem-level insights across malware families or firmware systems of binaries.
- **KnowledgeRAG:** Extending RAG with embeddings and knowledge graphs, grounding LLM reasoning in structured RE data for summarization, vulnerability reporting, and signature generation.
- **Agentic LLMs with AutoGen:** Introducing autonomous, tool-using LLM agents that can plan, reason, and iteratively interact with RE systems such as disassemblers and graph databases, enabling adaptive automation of workflows like large-scale triage and recursive malware family exploration.

---

## Bio

Dr. Malachi Jones is a Principal Cybersecurity AI/LLM Researcher and Manager at Microsoft, where he currently leads a team advancing red team agent autonomy within Microsoft Security AI (MSECAI). His present focus is on building autonomous red team agents, while his earlier work centered on fine-tuning large language models (LLMs) for security tasks and developing reverse engineering capabilities in Security Copilot.

With over 15 years in security research, Dr. Jones has contributed to both academia and industry. At MITRE, he advanced ML- and IR-based approaches for automated reverse engineering, and at Booz Allen Dark Labs, he specialized in embedded security and co-authored US Patent 10,133,871.

In addition to his work at Microsoft, Dr. Jones is the founder of Jones Cyber-AI, an organization dedicated to independent research and teaching initiatives. Through Jones Cyber-AI, he has developed and taught his specialized course, *Automating Reverse Engineering Processes with AI/ML, NLP, and LLMs*, at premier conferences including Black Hat USA (2019, 2021, 2023–2025) and RECON Montreal (2023–2025). His independent research in AI/ML, Graphs, and LLMs agents ensures his courses remain cutting-edge and aligned with the latest advances in cybersecurity and reverse engineering.

He previously served as an Adjunct Professor at the University of Maryland, College Park, and holds a B.S. in Computer Engineering from the University of Florida, as well as an M.S. and Ph.D. from Georgia Tech, where his research applied game theory to cybersecurity. His expertise continues to drive innovation in AI-driven cybersecurity and automated reverse engineering.

---

## Course Schedule

✅ **Overall Time Summary**

- **Total Instruction Time:** 1,485 minutes  
- **Total Hours:** 24.75 hours (≈ 24 hours 45 minutes)

---

## Session Details

### Module I: Introductions to Core Concepts and Techniques

| Session | Topic | Duration | Description |
|---|---|---:|---|
| Lecture 1 | Introduction to Auto RE | 60 min | - Challenges of Manual Reverse Engineering: This session examines the traditional, time-intensive challenges of manual reverse engineering in malware analysis, firmware analysis, vulnerability research, and software bill of material (SBOM) generation.<br>- Overcoming Hurdles with Advanced Technologies: We'll focus on addressing automation, scalability, and architectural challenges, and how applying AI, ML, Binary Analysis, NLP, and LLMs can lead to more efficient and effective processes in Cyber Security. |
| Lecture 2 | Introduction to Binary Analysis | 60 min | - Fundamentals of Binary Analysis: This lecture discusses the core aspects of binary analysis, with a focus on Intermediate Representation (IR) languages, including VEX and p-code, and their associated challenges.<br>- Exploring Tools for Analysis: We'll examine the use of pyvex in the angr framework and Ghidra's p-code API, demonstrating how these tools facilitate both static and dynamic analysis in binary analysis. |
| Lab 0 | Introduction to Blackfyre | 45 min | - Introduction to Blackfyre - Ghidra Plugin: This lecture introduces Blackfyre's first component, a Ghidra plugin designed for capturing binary data into a Binary Context Container (BCC), crucial for AI/ML and LLM data science projects.<br>- Blackfyre Python Library and Extensions: The session also covers Blackfyre's second component, a Python library for parsing BCC data and managing VEX IR, demonstrating its application in binary analysis and potential extensions to other disassemblers like IDA Pro and Binary Ninja. |
| Lecture | Introduction to Graphs | 45 min | Ontologies, comparing to relational databaes, knowledge graphs, etc… |
| Lab 1 | BinQL-Lite Lab | 60 min | In this lab, students implement a lightweight version of BinQL using Blackfyre, focusing on ontology design, constraints, and example queries for structured binary analysis. Through single-binary and system- or family-level analysis, the lab demonstrates how BinQL-Lite supports practical applications including vulnerability analysis, malware analysis, and firmware analysis. |
| Lecture 2 | Review of key ML Concepts | 30 min | - Introduce core ML concepts including feature representation, intuitive classification, and optimization techniques such as gradient descent and Adam.<br>- Cover loss functions and distance/similarity metrics (e.g., Euclidean distance, cosine similarity) used in model training and comparison.<br>- Discuss evaluation metrics including precision, recall, F1-score, and ROC for assessing classification performance. |
| Lecture 3 | Introduction to LLMs and Prompting — Capabilities, Limits, and Control | 75 min | This lecture introduces Large Language Models (LLMs) by explaining how transformer-based neural networks are trained via next-token prediction and why scale leads to emergent capabilities alongside probabilistic, non-deterministic behavior. It then examines prompt engineering as a mechanism for influencing LLM behavior—covering zero-shot and few-shot prompting, instruction framing, and retrieval augmentation—while emphasizing the fundamental limitations of prompting alone, motivating the use of structured program graphs, NL2GQL, fine-tuning, and agent-based orchestration throughout the remainder of the course. |
| Lab 2 | Integrating LLMs with BinQL-Lite for NL2GQL | 45 min | In this lab, students integrate an LLM with a lightweight BinQL-Lite interface to translate natural-language reverse engineering questions into graph queries (NL2GQL) over a binary analysis knowledge graph. This lab establishes a baseline pipeline that intentionally exposes the limitations of base models, which will be revisited in a later lab to demonstrate how fine-tuning significantly improves query accuracy, consistency, and insight quality. |

---

### Module II: Graphs for Reverse Engineering

| Session | Topic | Duration | Description |
|---|---|---:|---|
| Lecture 4 | Graph Fundamentals for Program Analysis | 60 min | Review graph theory basics and their application in program analysis, including CFGs, CGs, and DFGs. |
| Lab 3 | Behavioral Binary Similarity via Graph-Sampled Import Call Traces | 45 min | This lab compares binaries by sampling execution paths from a Neo4j program graph and extracting ordered import call sequences as behavioral fingerprints. By focusing on import workflows rather than CFG structure or instructions, the approach is more stable across different compilers, optimization levels, and architectures (e.g., x86 vs ARM). |
| Lab 4 | Graph-Driven Malware Analysis Lab | 30 min | This lab builds a graph-based malware analysis environment using a structured ontology of binaries, functions, basic blocks, call graphs, control-flow graphs, strings, and imports. The system enables clustering of related samples, discovery of shared components, capability mapping, and structural detection of obfuscation or anti-analysis features. Enriched string nodes—augmented via NER to classify domains, IP addresses, URLs, mutexes, and registry keys—support behavioral insights across malware families and campaigns. |
| Lab 5 | Graph-Based Vulnerability Analysis Lab | 30 min | This lab builds a graph-based vulnerability analysis environment on top of binaries modeled as Binary, Function, BasicBlock, ImportSymbol, StringLiteral, and their relationships (HAS_FUNCTION, ENTRY_BLOCK, BRANCHES_TO, CALLS_TO).<br><br>Analysts can:<br>- Detect unsafe API usage and vulnerable components<br>- Explore CFG-bounded exploit paths to risky sinks<br>- Identify reused vulnerable code across binaries<br>- Correlate code and libraries with NVD CVEs<br>- Highlight cyclomatically complex regions that also use dangerous APIs<br>- Find “dark” or rarely-visited/unreachable portions of the code that may hide subtle vulnerabilitie |
| Lecture 5 | BasicBlockRank : Efficient Ranking of Basic Blocks Inspired by PageRank | 45 min | - Introduction to BinaryRank: This lecture presents BinaryRank, an algorithm for static analysis of a binary's call graph and function control flow graphs, establishing a global rank for basic blocks.<br>- Efficiency and Application: We'll explore how BinaryRank, with its linear computational complexity, efficiently determines the importance of strings, function calls, and other data based on their connection to ranked basic blocks, contrasting its efficiency with the traditional PageRank algorithm. |
| Lab 6 | Implementing BasicBlockRank with BinQL | 45 min | BasicBock implmenation using BinQL |

---

### Module III: Neural Networks for Reverse Engineering, including Transformers

| Session | Topic | Duration | Description |
|---|---|---:|---|
| Lecture 6 | Introduction to Transformers | 90 min | - Cover the core components of Transformer architectures, including token embeddings, multi-head self-attention, position encoding, and the role of feed-forward networks in sequence modeling.<br>- Explain the concept and training objective of Masked Language Modeling (MLM), along with decoding strategies such as greedy decoding and beam search for generating coherent output sequences.<br>- Examine strategies for handling long-context sequences in Transformers, with a focus on sparse attention mechanisms—highlighting models like Longformer that improve scalability by reducing attention computation over extended inputs. |
| Lab 7 | Binary String Embeddings with Longformer MLM | 60 min | - **7.1 Advanced Tokenization**: Learn sophisticated techniques for tokenizing binary-derived text, including handling coding conventions (CamelCase, snake_case), compound identifiers, and domain-specific RE terminology.<br>- **7.2-7.3 Token Processing**: Preprocess symbolic reverse engineering data—specifically binary strings—into tokenized, model-ready inputs suitable for training with Masked Language Modeling (MLM).<br>- **7.4 Training**: Train a Longformer model on a large corpus of symbolic strings and implement methods to extract [CLS] token embeddings for use in similarity analysis.<br>- **7.5-7.6 Evaluation**: Compare context-aware embeddings from Longformer to static Word2Vec representations and OpenAI embeddings, evaluating their effectiveness on curated semantic similarity test cases with LLM-generated analysis. |
| Lecture 7 | Function name prediction with BinaryRank and MLM | 60 min | - Introduce the challenge of recovering semantic intent in stripped binaries, with a focus on the difficulty of analyzing leaf functions that lack symbolic metadata and callee context.<br>- Present a hybrid approach for function name prediction that combines transformer-based contextual embeddings with BinaryRank, a control-flow-informed method for selecting semantically relevant basic blocks.<br>- Explain how a transformer encoder-decoder architecture maps VEX IR instruction sequences to human-readable function names, capturing both local semantics and global control-flow structure. |
| Lab 8 | Function Name prediction with BinaryRank and MLM | 30 min | - Use a pretrained Longformer MLM to generate contextual embeddings of basic blocks from VEX IR sequences, forming the basis for function-level representation.<br>- Apply BinaryRank to select and weight key blocks based on control flow proximity, and aggregate their embeddings to represent the entire function.<br>- Use a transformer decoder to predict function names from these embeddings, evaluating the impact of incorporating symbolic context such as strings and imported functions. |
| Lecture 8 | Function and Binary Similarity at Scale Using Locality-Sensitive Hashing | 45 min | This lecture presents function similarity as a foundational scaling primitive for large-scale reverse engineering, enabling fast retrieval of related code across massive corpora. By introducing locality-sensitive hashing (LSH) and approximate nearest-neighbor search, students learn how function-level representations support lineage analysis, variant discovery, and grounded retrieval for downstream graph and LLM-based workflows. |
| Lab 9 | Scalable Function and Binary Similarity Analysis | 30 min | In this lab, students implement scalable function- and binary-level similarity search using approximate nearest-neighbor techniques such as locality-sensitive hashing (LSH) to retrieve related code across large corpora and integrate the results into a program graph by adding similarity edges between functions across different binaries. The lab frames similarity as a retrieval and prioritization primitive—supporting malware analysis, code reuse identification, binary lineage tracking, and vulnerability workflows such as variant discovery, patch impact analysis, and search-space reduction rather than direct vulnerability detection. |

---

### Module IV: Fine-Tuned LLMs and Agentic Reverse Engineering

| Session | Topic | Duration | Description |
|---|---|---:|---|
| Lecture | Fine-tune LLMs | 60 min | - Explore strategies for adapting large language models (LLMs), including full fine-tuning, parameter-efficient methods like Low-Rank Adaptation (LoRA), and model distillation.<br>- Examine quantization techniques for reducing model size and inference costs, and review practical tools and frameworks for fine-tuning LLMs.<br>- Discuss key hyperparameters for fine-tuning and how they impact model convergence, generalization, and downstream task performance. |
| Lab 10 | Fine-tune lab NL2GQL: Fine-tune LLMs lab | 60 min | NL2GQL |
| Lecture 10 | Agents and Agentic Workflows for Reverse Engineering | 45 min | This lecture introduces agent-based LLM systems that decompose complex reverse-engineering tasks into coordinated, goal-driven subtasks. Students examine practical frameworks such as LightRAG, AutoGen, MCP, and Prompty, focusing on how agents retrieve structured context, plan actions, verify results, and collaborate to scale analysis beyond single-prompt interactions. |
| Lab 11 | Patch Impact Analysis and Root-Cause Validation Using Graphs and LLMs | 45 min | This lab focuses on identifying where and how a security patch modifies a binary in response to a published CVE, using a combination of program graph analysis and LLM-assisted reasoning. Given an unpatched binary, a patched binary, and a security advisory, students locate the specific code regions affected by the patch and analyze whether the changes actually address the stated root cause. The lab demonstrates why understanding patch intent is critical for vulnerability validation, variant detection, and assessing residual risk beyond simply observing that a patch exists. |
| Lab 12 | Advanced Function and Whole-Binary Summarization Using LLMs, RAG, and BinQL | 60 min | This lab uses Large Language Models (LLMs) with Retrieval-Augmented Generation (RAG) to produce concise function-level and whole-binary summaries grounded in a binary analysis knowledge graph. Students use BinQL to retrieve structured program facts—such as imports, control flow, and execution-relevant code paths—and provide them to the LLM as context, enabling accurate and explainable summarization beyond raw disassembly. |
| Lab 13 | Multi-Agent Firmware Ecosystem Analysis Using Program Graphs and LLMs | 30 min | This lab treats a router firmware image as an ecosystem of interacting binaries rather than isolated programs. Using a Neo4j program graph and LLM-assisted analysis, students identify shared libraries, imports, and call relationships to uncover attack surfaces, reused components, and high-risk binaries across the firmware. The lab demonstrates how combining graph-based analysis with LLM-driven summarization enables system-level security insights that are difficult to obtain from single-binary reverse engineering. |
| Lab 14 | Multi-Agent N-Day Vulnerability Triage (Static) | 45 min | This lab uses a multi-agent LLM workflow and program graph evidence to statically triage N-day vulnerabilities when version and SBOM data are unreliable. By treating CVEs as hypotheses and filtering them using structural and semantic constraints derived from the code's actual execution paths, the lab produces an explainable, prioritized shortlist of vulnerabilities suitable for downstream dynamic validation. |
| Lecture | Yara Signature | 30 min | *(No additional details provided in source text.)* |
| Lab 15 | Graph-Driven N-Gram Analysis and Multi-Agent YARA Rule Synthesis | 45 min | This lab extends the binary analysis ontology with an Ngram entity that connects binaries to the distinctive byte-sequence patterns they contain. Students use the graph to discover binary-specific or family-specific n-gram clusters and automatically propose YARA-style detection patterns. A multi-agent workflow then validates, refines, and improves these candidate rules using structural graph context, coverage checks, and similarity analysis. |
