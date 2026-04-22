A Hybrid LangGraph Security Agent for Real-Time HTTP Injection Detection and Asynchronous Grey-Zone Response

Emil Patrick  
Dr.-Ing. Judith Leo  
Prof.-Ing. Anael Sam, PhD

## Abstract

HTTP-layer injection attacks remain a persistent threat to web applications because malicious payloads can be embedded across multiple request fields and often resemble legitimate user input. Traditional web application firewalls rely heavily on signatures and rules, while fully agentic security pipelines can introduce unacceptable latency in live request handling. This paper presents a hybrid security architecture that combines a fast inline machine learning detector with asynchronous large language model reasoning (LLM) orchestrated through LangGraph. The proposed system classifies every incoming HTTP request in real time using an inline detector and applies two confidence thresholds to route traffic into three tiers: immediate blocking for high-confidence attacks, immediate pass-through for low-confidence benign requests, and asynchronous grey-zone review for uncertain cases. The grey-zone path uses a LangGraph-based agent with security-specific tools for request inspection, IP reputation lookup, incident logging, temporary blocking, and alert generation. A FastAPI server exposes operational endpoints for live analysis, incident lookup, request tracking, and aggregate statistics, while SQLite provides durable storage for incident records and source-IP reputation. The design goal is to preserve low latency on the live path while still enabling deeper contextual reasoning for ambiguous traffic. This draft reports the system design, implementation, and evaluation plan of the prototype. Full quantitative results remain future work pending integration of the final trained HTTP injection classifier and batch evaluation pipeline.

**Keywords:** HTTP injection detection, LangGraph, security agent, grey-zone analysis, FastAPI, SQLite, web application security, agentic orchestration

## 1. Introduction

Web applications continue to serve as a primary delivery surface for injection attacks, including SQL injection, cross-site scripting, command injection, LDAP injection, XML/XPath injection, and related payload-based exploitation techniques. These attacks are especially difficult to handle in production because defenders must make decisions under strict latency budgets while malicious payloads are often obfuscated, distributed across fields, or intentionally shaped to resemble benign traffic.

Signature-driven web application firewalls remain operationally useful, but they are brittle against payload mutation, encoding tricks, and previously unseen combinations of attack syntax. Purely rule-based systems can be bypassed when attackers alter spacing, casing, comments, delimiters, or encoding layers. On the other end of the design space, language-model-based security analysis can offer richer contextual reasoning, but using an LLM synchronously on every live request is operationally expensive and can degrade user experience.

This tension creates a design problem: how can a defensive system preserve millisecond-level inline performance for most HTTP traffic while still applying richer reasoning to ambiguous cases? This paper addresses that problem with a hybrid architecture that uses a fast machine learning detector on the live path and invokes a LangGraph-based LLM agent only for uncertain requests. The central idea is simple: not every request deserves agentic analysis. Most requests should be resolved immediately, while only the grey zone should be escalated.

The prototype described in this paper was implemented as a working system rather than a purely conceptual design. It includes a FastAPI service, a confidence-routed detection pipeline, a LangGraph workflow for asynchronous analysis, a SQLite-backed incident and reputation store, and operational endpoints for incident retrieval and request status tracking.

The main contributions of this work are:

- A hybrid API-led security architecture that separates low-latency inline decisions from slower agentic reasoning.
- A three-tier confidence routing strategy for HTTP request analysis: high-confidence block, low-confidence pass-through, and asynchronous grey-zone review.
- A LangGraph-based security agent equipped with task-specific tools for request inspection, history lookup, incident logging, IP blocking, and alerting.
- A persistent incident and IP-reputation layer implemented in SQLite to support graduated response actions and future research evaluation.
- An explicit comparison point between an API-led architecture and a full-LangGraph orchestration variant, enabling future evaluation of orchestration placement rather than detection semantics alone.

## 2. Problem Setting and Scope

The system is designed for HTTP-layer injection detection and response. It focuses on attacks delivered through request URLs, query parameters, headers, and bodies. The in-scope classes currently include:

- SQL injection
- Cross-site scripting
- Command injection
- LDAP injection
- XML/XPath injection
- Header injection

The current prototype is intentionally narrower than a full web security platform. The following are out of scope:

- Non-HTTP attacks such as SSH-, DNS-, or raw TCP-level attacks
- Volumetric denial-of-service attacks
- Authentication and authorization flaws not expressed as injection payloads

The operational problem is binary request classification with response orchestration under latency constraints. For each incoming request, the system must decide whether the request is benign or malicious, assign an action, and preserve enough structured evidence for later analysis. In practice, this means the system must trade off detection confidence, false positives, and response latency instead of optimizing only one variable.

## 3. System Overview

The implemented prototype uses a hybrid inline/async architecture. Every incoming HTTP request is normalized into a structured representation containing request ID, timestamp, method, URL, headers, body, and source IP. A detector then produces an attack confidence score in the range [0, 1]. Two configurable thresholds partition the request stream into three decision tiers:

- confidence >= HIGH_THRESHOLD (0.95 by default): treat as high-confidence attack and block inline.
- confidence <= LOW_THRESHOLD (0.15 by default): treat as benign and pass inline.
- LOW_THRESHOLD < confidence < HIGH_THRESHOLD: treat as grey-zone traffic and queue for asynchronous LangGraph analysis.

This routing design ensures that the live API path remains fast for clear-cut requests while ambiguous traffic receives richer analysis after the immediate response has already been returned to the caller.

### 3.1 Live Request Path

The default implementation places the live routing logic in FastAPI. When a request arrives at `/analyze`, the server:

1. checks whether the source IP is already banned,
2. parses and normalizes the HTTP request,
3. runs the detector,
4. routes the request based on confidence,
5. returns a structured response including `request_id`, `confidence`, `tier`, `decision`, and `action_taken`.

This design makes the transport layer the owner of operational routing while keeping LangGraph focused on the grey zone.

### 3.2 Grey-Zone Analysis Path

Grey-zone requests are passed through immediately but queued for background analysis. A thread pool executes the LangGraph workflow without blocking the live response. The workflow prepares request context, invokes the LLM with bound security tools, and records the resulting decision in persistent storage. The system also tracks per-request analysis state so clients can query completion status later via `/request/{request_id}`.

Figure 1 summarizes the default API-led architecture and makes the separation between the low-latency inline path and the asynchronous grey-zone review path explicit.

```text
+------------------------------+
| HTTP client / traffic source |
+------------------------------+
               |
               v
+-----------------------------+
| FastAPI service: /analyze   |
+-----------------------------+
               |
               v
      +---------------------+        yes        +-----------------------+
      | Source IP banned?   | ----------------> | Inline block response |
      +---------------------+                   +-----------------------+
               | no                                      |
               v                                         v
+-----------------------------+               +------------------------------+
| Request normalization       |               | Returned immediately to      |
+-----------------------------+               | client                       |
               |                              +------------------------------+
               v
+-----------------------------+
| Inline detector             |
| confidence in [0,1]         |
+-----------------------------+
               |
               v
      +---------------------+
      | Confidence router   |
      +---------------------+
        /          |          \
       /           |           \
      v            v            v
+-------------+ +-------------+ +----------------------+
| confidence  | | confidence  | | grey-zone /          |
| >= HIGH     | | <= LOW      | | uncertain request    |
+-------------+ +-------------+ +----------------------+
      |              |                    |
      v              v                    v
+-------------+ +-------------+ +---------------------------+
| auto_respond| | pass_through| | Return under_review       |
+-------------+ +-------------+ | immediately to client     |
      |              |          +---------------------------+
      |              |                    |
      |              |                    v
      |              |          +---------------------------+
      |              |          | Background queue /        |
      |              |          | thread pool               |
      |              |          +---------------------------+
      |              |                    |
      |              |                    v
      |              |          +---------------------------+
      |              |          | LangGraph security agent  |
      |              |          +---------------------------+
      |              |                    |
      |              |                    v
      |              |          +---------------------------+
      |              |          | Security tools            |
      |              |          | - inspect_request_fields  |
      |              |          | - check_ip_history        |
      |              |          | - log_security_incident   |
      |              |          | - block_ip                |
      |              |          | - send_alert              |
      |              |          +---------------------------+
      |              |                    |
      |              |                    v
      |              |          +---------------------------+
      |              |          | Post-hoc actions          |
      |              |          | alert / temp ban / record |
      |              |          +---------------------------+
      |              |                    |
      |              |                    v
      |              |          +---------------------------+
      +------------+ |          | SQLite                    |
                   | |          | incidents + ip_reputation |
                   | |          +---------------------------+
                   | |                    ^
                   | +--------------------+
                   +----------------------+

Client status polling:
HTTP client ---> FastAPI service: /request/{request_id} ---> SQLite
```

*Figure 1. Hybrid architecture of the proposed system. FastAPI owns the live routing decision, while LangGraph is reserved for asynchronous analysis of grey-zone requests.*

## 4. Architecture

### 4.1 Tiered Detection Pipeline

The core pipeline can be summarized as follows:

- HTTP request arrives at `FastAPI /analyze`.
- The detector evaluates the normalized request and produces a confidence score.
- High-confidence attack traffic is routed to `auto_respond`, which blocks the request, logs the incident, and may apply a temporary ban for repeat offenders.
- Low-confidence benign traffic is routed to `pass_through`, which allows the request and logs it as benign.
- Grey-zone traffic is returned immediately as `under_review` and queued for asynchronous LangGraph analysis.

The design objective is not to maximize agent usage. It is to minimize unnecessary agent usage while preserving an escalation path for ambiguous samples.

### 4.2 Default API-Led Variant

In the main branch, FastAPI owns the live request decisions for banned, high-confidence, low-confidence, and grey-zone outcomes. LangGraph is used only for the background review stage. This is the cleaner operational baseline because the latency-critical path stays in conventional service code.

### 4.3 Full-LangGraph Variant

The repository also documents an experimental full-graph variant in which transport remains in FastAPI but orchestration ownership moves into LangGraph. Ban checks, detection, and tier routing become graph responsibilities, while grey-zone analysis is still asynchronous to keep comparison fair. The architectural significance of this second variant is that it creates a future evaluation axis: whether a fully graph-owned workflow improves clarity, extensibility, or maintainability enough to justify added execution complexity.

## 5. Implementation Details

### 5.1 Detector Layer

The detector module defines the thresholds, request normalization logic, model loading hook, probability prediction hook, and a routing function for graph use. At the time of writing, the detector is still backed by a placeholder scoring implementation that looks for suspicious lexical patterns in the URL and body. This is an implementation scaffold, not the final research model.

That limitation matters. The prototype demonstrates the orchestration pattern and live system integration, but it should not be presented as a finished empirical detector until the real trained classifier is plugged into `load_model()` and `predict()`.

### 5.2 Response Nodes

Two non-LLM fast-path nodes handle the clear cases:

- `auto_respond` processes high-confidence attacks by updating IP reputation, logging the incident, blocking the request, and escalating to a temporary IP ban for repeat offenders.
- `pass_through` processes low-confidence benign traffic by updating reputation and logging the request as benign.

The use of dedicated response nodes prevents trivial cases from consuming LLM resources and keeps the decision semantics explicit.

### 5.3 LangGraph Security Agent

The grey-zone workflow is implemented as a LangGraph state machine. Its state includes the request payload, detection result, message history, response data, and accumulated incident log entries. The graph starts by converting the request and detector output into a structured prompt context. It then invokes a chat model configured through `langchain_openai` and OpenRouter. If the model requests tools, execution loops through a `ToolNode` until the interaction completes.

The current graph topology is intentionally small:

```text
START -> prepare_llm_context -> security_chatbot <-> security_tools -> END
```

This is enough to support tool-augmented reasoning without overcomplicating the first implementation.

### 5.4 Security Tools

The security agent is equipped with a minimal but practical toolset:

- `inspect_request_fields` decomposes the request and surfaces headers, body, and query parameters in a readable form.
- `check_ip_history` retrieves IP reputation and recent incident history from SQLite.
- `log_security_incident` records the LLM decision, action, and reasoning.
- `block_ip` sets a temporary IP ban with a configurable duration.
- `send_alert` writes alert events to a log file as a stand-in for downstream notification systems.

These tools are enough to support a plausible security analyst workflow: inspect, contextualize, decide, record, and escalate.

### 5.5 Persistence and Reputation Tracking

SQLite is used as the persistent control-plane store. Two tables matter:

- `incidents` stores request-level evidence such as source IP, confidence, decision, decision source, action taken, and optional LLM reasoning.
- `ip_reputation` stores per-IP summary state including first seen time, last seen time, total requests, attack count, grey-zone count, escalation level, and ban expiry.

This persistence model supports more than logging. It enables graduated response behavior by making prior history available to both inline logic and the grey-zone agent.

### 5.6 API Surface

The FastAPI service exposes the following operational endpoints:

- `POST /analyze` for live request analysis
- `GET /ip/{source_ip}` for reputation and recent incident lookup
- `GET /incidents` for recent incident retrieval
- `GET /stats` for aggregate counts and current thresholds
- `GET /request/{request_id}` for per-request processing status

This API makes the system usable both as a research prototype and as an observable service.

## 6. Graduated Response Strategy

The system supports layered responses instead of a single binary outcome. In the current prototype, the effective actions are:

- `log_only` for benign traffic
- `block` for high-confidence attacks
- `temp_ban` for repeated offending behavior
- `under_review` for grey-zone requests awaiting asynchronous decision
- `alert` as an available LLM action in suspicious cases

This design reflects a practical security posture. Not every suspicious event should trigger a permanent ban, and not every uncertain request should be blocked before analysis. By tracking reputation and repeat behavior over time, the system can react proportionally rather than purely per-request.

## 7. Why LangGraph Fits This Problem

LangGraph is not used here as decoration. It is used where the problem actually benefits from controlled agentic orchestration: the ambiguous middle of the decision distribution.

Three properties make it a good fit:

- The grey zone often requires multi-step reasoning rather than single-shot classification.
- Tool access is necessary because historical IP context and durable incident logging are part of the decision process.
- The workflow benefits from explicit state transitions instead of opaque chained prompts.

At the same time, the design avoids the common mistake of sending every request through the graph. That would be expensive, harder to defend operationally, and unnecessary for obviously benign or obviously malicious traffic.

## 8. Evaluation Plan

The prototype is implementation-complete enough to support future evaluation, but the quantitative research phase is still pending. A credible evaluation should answer four questions:

1. How accurate is the final detector on labeled HTTP injection data?
2. How many requests fall into each tier under realistic traffic?
3. What is the latency cost of the live path and the grey-zone path?
4. Does agentic review improve outcomes on ambiguous cases without creating unacceptable operational overhead?

### 8.1 Planned Metrics

The evaluation should at minimum report:

- accuracy
- precision
- recall
- F1-score
- false positive rate
- false negative rate
- inline inference latency
- grey-zone completion latency
- escalation rate
- fraction of requests requiring LLM analysis

### 8.2 Planned Experimental Comparisons

The repository structure naturally supports several useful comparisons:

- inline detector alone versus hybrid detector plus LangGraph review
- API-led orchestration versus full-LangGraph orchestration
- threshold settings that change the size of the grey zone
- attacker classes or payload families across SQLi, XSS, command injection, and related attacks

### 8.3 Data Sources

A rigorous experimental section should combine multiple data origins rather than relying on a single benchmark source. The likely composition is:

- public payload corpora and benchmark datasets
- synthetic attack traffic generated with offensive tooling against controlled targets
- benign HTTP traffic captured from normal application use
- live or replayed honeypot traffic where appropriate

The important methodological point is that the orchestration architecture and the detector should be evaluated together, not as isolated components.

## 9. Limitations

This draft should be read as a system paper draft, not a finished empirical performance paper. The current limitations are explicit:

- The detector still uses placeholder scoring logic rather than the final trained model.
- Batch evaluation scripts and export pipelines are not yet implemented in the repo.
- The current tests are smoke-level checks, not a full validation suite.
- Alerting is file-based rather than integrated with a real notification or SIEM pipeline.
- The LLM path depends on external model access and therefore introduces operational dependency considerations.

These are not fatal flaws, but they do define what can and cannot be claimed honestly at this stage.

## 10. Discussion

The most important design decision in this system is not the use of LangGraph by itself. It is the placement of agentic reasoning behind a confidence gate. That placement makes the architecture defensible for real deployment because it preserves latency for the majority of traffic while still reserving deeper analysis for the samples where it is most likely to matter.

This also makes the system academically interesting. It creates a bridge between conventional request classification and agentic security response, allowing the research question to move beyond "can an LLM detect attacks?" toward a more grounded systems question: where should agentic orchestration sit in a live defensive pipeline, and under what confidence regime does it provide net value?

## 11. Conclusion

This paper draft presented a hybrid LangGraph security agent for HTTP injection detection and response. The system combines a fast inline detector with asynchronous grey-zone reasoning, persistent incident logging, IP reputation tracking, and graduated response actions. The implemented prototype demonstrates a practical orchestration pattern for deploying agentic analysis without forcing all traffic through an expensive reasoning layer.

The current contribution is strongest as a systems and architecture paper draft grounded in a working prototype. The next step is straightforward but non-trivial: integrate the final trained detector, build the batch evaluation pipeline, and generate quantitative results that test the architectural claims under realistic traffic and attack conditions. If those results hold, the system can support a stronger argument that agentic orchestration is most useful not as a replacement for inline detection, but as a targeted second-stage mechanism for ambiguous security events.

## 12. Candidate References

The draft below needs a proper literature pass before submission. These are placeholder reference slots to replace with verified sources from the thesis library:

- [REF] OWASP material on injection risks and web application security categories.
- [REF] Prior work on machine learning for SQL injection and XSS detection.
- [REF] Prior work on deep learning for payload classification and intrusion detection.
- [REF] LangGraph or graph-based agent orchestration documentation or technical references.
- [REF] Literature on explainability, human-in-the-loop review, or contextual reasoning in security operations.
- [REF] Research comparing rule-based versus learned web attack detection.

## Appendix A. Repo-to-Paper Mapping

The draft is grounded in the current repository layout:

- `app/api/server.py` implements the API-led live routing path.
- `app/detection/detector.py` implements request normalization, thresholds, and detector hooks.
- `app/graph/security_agent.py` implements the grey-zone LangGraph workflow.
- `app/graph/response_nodes.py` implements the high-confidence and benign fast paths.
- `app/tools/security_tools.py` implements the analyst tools used by the LLM.
- `app/storage/database.py` implements the SQLite incident and reputation layer.
- `docs/architecture_comparison.md` documents the API-led and full-graph variants.

That mapping matters because it keeps the manuscript tied to a concrete artifact instead of drifting into generic agent-security prose.
