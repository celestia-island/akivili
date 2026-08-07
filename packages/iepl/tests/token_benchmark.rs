use anyhow::{Context, Result};

use akivili_iepl::IeplEngine;

fn estimate_tokens(text: &str) -> usize {
    (text.len() as f64 / 4.0).ceil() as usize
}

struct BenchmarkResult {
    label: String,
    source_size: String,
    source_tokens: usize,
    js_size: String,
    js_tokens: usize,
    elapsed_us: u128,
}

fn run_benchmark(label: &str, ts_code: &str) -> Result<BenchmarkResult> {
    let engine = IeplEngine::new();
    let source_len = ts_code.len();
    let source_tokens = estimate_tokens(ts_code);

    let start = std::time::Instant::now();
    let result = engine.transpile(ts_code);
    let elapsed = start.elapsed().as_micros();

    let js_code = result.context("transpile should succeed")?.js_code;
    let js_len = js_code.len();
    let js_tokens = estimate_tokens(&js_code);

    Ok(BenchmarkResult {
        label: label.to_string(),
        source_size: format!("{} chars", source_len),
        source_tokens,
        js_size: format!("{} chars", js_len),
        js_tokens,
        elapsed_us: elapsed,
    })
}

#[test]
fn token_consumption_benchmark() -> Result<()> {
    let scenarios: Vec<(&str, &str)> = vec![
        (
            "Simple (2 calls)",
            r#"
import { file_read } from 'kalos';
const r: string = file_read({path: "x"});
import { report } from 'hubris'; report({text: r});
"#,
        ),
        (
            "Multi-tool (3 calls)",
            r#"
import { navigate, screenshot } from 'web_automation';
const review: string = navigate({ browser_id: "b1", url: "http://example.com" });
const deps: string = screenshot({ browser_id: "b1" });
import { report } from 'hubris'; report({ text: review + deps });
"#,
        ),
        (
            "Complex data (memory query)",
            r#"
import { memory_query } from 'philia';
interface MemoryNode { id: string; label: string; type_: string; }
interface MemoryEdge { source: string; target: string; relation: string; }

const query_result: string = memory_query({ query: "project architecture", limit: 50 });
const parsed: MemoryNode[] = JSON.parse(query_result).nodes;
const filtered: MemoryNode[] = parsed.filter((n: MemoryNode) => n.type_ === "concept");
const summaries: string[] = filtered.map((n: MemoryNode) => n.label);
import { report } from 'hubris'; report({ text: summaries.join(", ") });
"#,
        ),
        (
            "Recursive tree",
            r#"
interface TodoNode { id: string; title: string; children: TodoNode[]; }

function traverse(node: TodoNode, depth: number): string[] {
    const items: string[] = [`${"  ".repeat(depth)}- ${node.title}`];
    for (const child of node.children) {
        const childItems: string[] = traverse(child, depth + 1);
        for (const item of childItems) {
            items.push(item);
        }
    }
    return items;
}

import { navigate } from 'web_automation';
const result: string = navigate({ browser_id: "b1", url: "http://example.com" });
const todos: TodoNode[] = JSON.parse(result).tasks;
const output: string[] = [];
for (const todo of todos) {
    const lines: string[] = traverse(todo, 0);
    for (const line of lines) {
        output.push(line);
    }
}
import { report } from 'hubris'; report({ text: output.join("\n") });
"#,
        ),
        (
            "Long chain (8 calls)",
            r#"
import { file_read } from 'kalos';
import { navigate, screenshot, list } from 'web_automation';
const f1: string = file_read({ path: "src/main.rs" });
const f2: string = file_read({ path: "src/lib.rs" });
const f3: string = file_read({ path: "Cargo.toml" });
const review1: string = navigate({ browser_id: "b1", url: "http://example.com/security" });
const review2: string = screenshot({ browser_id: "b1" });
const deps: string = list({});
const combined: string = `Review 1: ${review1}\nReview 2: ${review2}\nDeps: ${deps}`;
import { report } from 'hubris'; report({ text: combined });
"#,
        ),
    ];

    let mut results: Vec<BenchmarkResult> = Vec::new();
    for (label, code) in &scenarios {
        results.push(run_benchmark(label, code)?);
    }

    eprintln!(
        "\n╔══════════════════════════════════════════════════════════════════════════════════════╗"
    );
    eprintln!(
        "║ IEPL Token Consumption Benchmark                                                     ║"
    );
    eprintln!(
        "╠══════════════════════════════════════════════════════════════════════════════════════╣"
    );
    eprintln!(
        "║ {:<22} │ {:>14} │ {:>8} │ {:>14} │ {:>8} │ {:>10} ║",
        "Scenario", "Source Size", "Src Tok", "JS Size", "JS Tok", "Time (μs)"
    );
    eprintln!(
        "╠══════════════════════════════════════════════════════════════════════════════════════╣"
    );
    for r in &results {
        eprintln!(
            "║ {:<22} │ {:>14} │ {:>8} │ {:>14} │ {:>8} │ {:>10} ║",
            r.label, r.source_size, r.source_tokens, r.js_size, r.js_tokens, r.elapsed_us
        );
    }
    eprintln!(
        "╚══════════════════════════════════════════════════════════════════════════════════════╝"
    );
    eprintln!();

    assert!(!results.is_empty(), "should have benchmark results");
    for r in &results {
        assert!(
            r.source_tokens > 0,
            "{}: source_tokens should be > 0, got {}",
            r.label,
            r.source_tokens
        );
        assert!(
            !r.source_size.is_empty(),
            "{}: source_size should not be empty, got {}",
            r.label,
            r.source_size
        );
    }
    Ok(())
}
