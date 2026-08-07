use anyhow::{Result, anyhow};
use std::rc::Rc;

use swc_core::{
    common::{FileName, GLOBALS, Mark, SourceMap},
    ecma::{
        ast::{Pass, Program},
        codegen::{Config, Emitter, text_writer::JsWriter},
        parser::{Parser, StringInput, Syntax, TsSyntax, lexer::Lexer},
        transforms::typescript::strip,
    },
};

use crate::ast_validator;

#[derive(Debug)]
pub struct TranspileResult {
    pub js_code: String,
}

pub struct IeplEngine {
    cm: Rc<SourceMap>,
}

impl Default for IeplEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl IeplEngine {
    pub fn new() -> Self {
        Self {
            cm: Rc::new(SourceMap::default()),
        }
    }

    pub fn transpile(&self, ts_code: &str) -> Result<TranspileResult> {
        let violations = ast_validator::validate_ast(ts_code)?;
        if !violations.is_empty() {
            let details: Vec<String> = violations
                .iter()
                .map(|v| {
                    format!(
                        "[{}] {} (line {}, col {})",
                        v.kind, v.message, v.line, v.column
                    )
                })
                .collect();
            return Err(anyhow!(
                "AST security validation failed:\n{}",
                details.join("\n")
            ));
        }

        GLOBALS.set(&Default::default(), || self.transpile_inner(ts_code))
    }

    fn transpile_inner(&self, ts_code: &str) -> Result<TranspileResult> {
        let fm = self.cm.new_source_file(
            FileName::Custom("iepl-input".into()).into(),
            ts_code.to_string(),
        );

        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();

        let mut program = self.parse_ts(&fm)?;

        let mut pass = strip(unresolved_mark, top_level_mark);
        pass.process(&mut program);

        let js_code = self.emit(&program)?;
        Ok(TranspileResult { js_code })
    }

    fn parse_ts(&self, fm: &swc_core::common::SourceFile) -> Result<Program> {
        let lexer = Lexer::new(
            Syntax::Typescript(TsSyntax {
                tsx: false,
                decorators: true,
                dts: false,
                no_early_errors: false,
                disallow_ambiguous_jsx_like: false,
            }),
            Default::default(),
            StringInput::from(fm),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        parser
            .parse_program()
            .map_err(|e| anyhow!("TypeScript parse error: {:?}", e))
    }

    fn emit(&self, program: &Program) -> Result<String> {
        let mut buf = Vec::new();
        {
            let writer = JsWriter::new(self.cm.clone(), "\n", &mut buf, None);
            let mut emitter = Emitter {
                cfg: Config::default().with_minify(false),
                cm: self.cm.clone(),
                comments: None,
                wr: writer,
            };
            emitter.emit_program(program)?;
        }
        String::from_utf8(buf).map_err(|e| anyhow!("UTF-8 conversion error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_transpile() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"const x: number = 42; console.log(x);"#;
        let result = engine.transpile(ts)?;
        assert!(result.js_code.contains("42"));
        assert!(!result.js_code.contains("number"));
        Ok(())
    }

    #[test]
    fn test_type_strip() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"
interface Foo { name: string; age: number; }
const foo: Foo = { name: "test", age: 1 };
console.log(foo.name);
"#;
        let result = engine.transpile(ts)?;
        assert!(!result.js_code.contains("interface"));
        assert!(result.js_code.contains("foo"));
        Ok(())
    }

    #[test]
    fn test_async_function() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"
async function fetchData(url: string): Promise<string> {
    return "data";
}
"#;
        let result = engine.transpile(ts)?;
        assert!(result.js_code.contains("fetchData"));
        assert!(!result.js_code.contains("Promise<string>"));
        Ok(())
    }

    #[test]
    fn test_parse_error() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"const x: number = ;"#;
        let result = engine.transpile(ts);
        assert!(result.is_err());
        // Verify the error is specifically about parsing, not an unrelated failure.
        let err = result.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("parse"),
            "expected a parse error, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn test_tool_call_style() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"
import { navigate } from 'web_automation';
const result: string = await navigate({ browser_id: "b1", url: "http://test.com" });
console.log(result);
"#;
        let result = engine.transpile(ts)?;
        assert!(result.js_code.contains("navigate"));
        assert!(!result.js_code.contains(": string"));
        Ok(())
    }

    #[test]
    fn test_ast_validation_rejects_eval() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"eval("console.log(1)")"#;
        let result = engine.transpile(ts);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("eval_call"));
        Ok(())
    }

    #[test]
    fn test_ast_validation_rejects_process() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"const x = process.env"#;
        let result = engine.transpile(ts);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("forbidden_global_access"));
        Ok(())
    }

    #[test]
    fn test_arrow_with_type_params() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"
const parse = <T>(input: string): T => {
    return JSON.parse(input) as T;
};
"#;
        let result = engine.transpile(ts)?;
        assert!(result.js_code.contains("parse"));
        assert!(result.js_code.contains("JSON.parse"));
        assert!(!result.js_code.contains("string"));
        Ok(())
    }

    #[test]
    fn test_async_await_complex() -> Result<()> {
        let engine = IeplEngine::new();
        let ts = r#"
import { navigate } from 'web_automation';
async function processItems(items: string[]): Promise<void> {
    for (const item of items) {
        const result: string = await navigate({ browser_id: "b1", url: item });
        console.log(result);
    }
}
"#;
        let result = engine.transpile(ts)?;
        assert!(result.js_code.contains("async"));
        assert!(result.js_code.contains("await"));
        assert!(result.js_code.contains("processItems"));
        assert!(!result.js_code.contains("string[]"));
        assert!(!result.js_code.contains("Promise<void>"));
        Ok(())
    }
}
