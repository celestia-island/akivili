use criterion::{Criterion, black_box, criterion_group, criterion_main};

use akivili_iepl::IeplEngine;

const TS_SIMPLE: &str = r#"
import { navigate } from 'web_automation';
const result: string = await navigate({ browser_id: "b1", url: "http://test.com" });
console.log(result);
"#;

const TS_MEDIUM: &str = r#"
import { navigate, screenshot } from 'web_automation';
import { file_write, file_read } from 'kalos';

async function processUrls(urls: string[]): Promise<void> {
    for (const url of urls) {
        const navResult: string = await navigate({ browser_id: "b1", url });
        const screenshot: string = await screenshot({ browser_id: "b1" });
        await file_write({ path: "/tmp/out.txt", content: navResult + screenshot });
        const readBack: string = await file_read({ path: "/tmp/out.txt" });
        console.log(readBack);
    }
}
"#;

const TS_LARGE: &str = r#"
import { navigate, screenshot, keypress, mouse_click } from 'web_automation';
import { file_write, file_read, file_edit, file_list } from 'kalos';
import { memory_store, memory_query } from 'philia';
import { goal_create, goal_task_create, goal_task_complete } from 'skopeo';

interface StepResult { step: number; status: string; data: string; }

async function complexWorkflow(targetUrl: string, maxSteps: number): Promise<StepResult[]> {
    const results: StepResult[] = [];
    await goal_create({ description: "Automated browsing workflow", priority: "high" });

    for (let i = 0; i < maxSteps; i++) {
        const navResult: string = await navigate({ browser_id: "b1", url: targetUrl });
        const screenshot: string = await screenshot({ browser_id: "b1" });
        await memory_store({ key: `step_${i}`, value: navResult, category: "workflow" });

        if (i % 3 === 0) {
            await keypress({ browser_id: "b1", key: "Enter" });
        }
        if (i % 5 === 0) {
            await mouse_click({ browser_id: "b1", x: 100, y: 200 });
        }

        const files: string[] = await file_list({ path: "/tmp" });
        await file_write({ path: `/tmp/step_${i}.txt`, content: JSON.stringify({ navResult, screenshot, files }) });

        const memResult: string = await memory_query({ query: `step_${i}`, limit: 5 });
        await goal_task_create({ goal_id: "g1", description: `Task ${i}` });
        await goal_task_complete({ task_id: `t${i}` });

        results.push({ step: i, status: "completed", data: memResult });
    }
    return results;
}
"#;

fn bench_transpile_small(c: &mut Criterion) {
    let engine = IeplEngine::new();
    c.bench_function("transpile_small", |b| {
        b.iter(|| engine.transpile(black_box(TS_SIMPLE)))
    });
}

fn bench_transpile_medium(c: &mut Criterion) {
    let engine = IeplEngine::new();
    c.bench_function("transpile_medium", |b| {
        b.iter(|| engine.transpile(black_box(TS_MEDIUM)))
    });
}

fn bench_transpile_large(c: &mut Criterion) {
    let engine = IeplEngine::new();
    c.bench_function("transpile_large", |b| {
        b.iter(|| engine.transpile(black_box(TS_LARGE)))
    });
}

fn bench_validate_ast(c: &mut Criterion) {
    c.bench_function("validate_ast", |b| {
        b.iter(|| akivili_iepl::validate_ast(black_box(TS_MEDIUM)))
    });
}

criterion_group!(
    benches,
    bench_transpile_small,
    bench_transpile_medium,
    bench_transpile_large,
    bench_validate_ast,
);
criterion_main!(benches);
