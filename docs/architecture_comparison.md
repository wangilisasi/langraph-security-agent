# Architecture Comparison

## Branches

### `main`
Default API-led architecture.

- FastAPI owns live threshold routing
- FastAPI decides banned / high / low / grey outcomes for incoming traffic
- LangGraph is only used for asynchronous grey-zone analysis
- Best fit when low-latency request handling is the operational priority

### `experiment/full-langgraph-orchestration`
Experimental full-LangGraph architecture.

- FastAPI is a thin transport wrapper
- LangGraph owns ban checks, detection, routing, and immediate fast-path decisions
- Grey-zone requests still return immediately and are analyzed asynchronously in the background
- Best fit when a single workflow engine owning the decision pipeline is the design priority

## Key Difference

The main architectural difference is **where orchestration lives**.

### API-led (`main`)
- transport and orchestration are partly co-located in FastAPI
- easier to reason about operationally
- simpler live request path
- LangGraph is scoped to high-value uncertain cases only

### Full-LangGraph (`experiment/full-langgraph-orchestration`)
- transport remains in FastAPI, but decision orchestration moves into LangGraph
- cleaner single-owner workflow story
- easier to present as a fully agentic control flow
- more graph-centric design, with slightly more complexity in execution plumbing

## Shared Behavior

Both variants intentionally preserve:
- inline handling for clear high-confidence and low-confidence cases
- asynchronous grey-zone analysis
- SQLite-backed incident logging and IP reputation
- the same detector thresholds and response-node logic

This makes comparison fairer because the main change is orchestration style, not detection semantics.

## Evaluation Questions

When comparing the two branches, useful questions include:
- Does full-graph orchestration improve maintainability or conceptual clarity?
- Does it introduce measurable latency or operational complexity?
- Which variant is easier to explain and defend in the thesis?
- Which variant is easier to extend with future nodes, policies, or evaluators?
