use anyhow::{Result, anyhow};
use std::rc::Rc;

use swc_core::{
    common::{FileName, GLOBALS, SourceMap},
    ecma::{
        ast::{Callee, Expr, MemberExpr, MemberProp, MetaPropKind, NewExpr, WithStmt},
        parser::{Lexer, Parser, StringInput, Syntax, TsSyntax},
        visit::{Visit, VisitWith},
    },
};

use crate::security_constants::*;

#[derive(Debug)]
pub struct AstViolation {
    pub kind: String,
    pub message: String,
    pub line: usize,
    pub column: usize,
}

fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let up_to = &source[..offset.min(source.len())];
    let mut line = 1usize;
    let mut last_nl = 0usize;
    for (i, b) in up_to.as_bytes().iter().enumerate() {
        if *b == b'\n' {
            line += 1;
            last_nl = i + 1;
        }
    }
    let col = up_to.len() - last_nl + 1;
    (line, col)
}

struct SecurityVisitor {
    violations: Vec<AstViolation>,
    source: String,
}

impl SecurityVisitor {
    fn new(source: String) -> Self {
        Self {
            violations: Vec::new(),
            source,
        }
    }

    fn add(&mut self, kind: &str, message: &str, byte_offset: usize) {
        let (line, column) = byte_offset_to_line_col(&self.source, byte_offset.saturating_sub(1));
        self.violations.push(AstViolation {
            kind: kind.to_string(),
            message: message.to_string(),
            line,
            column,
        });
    }

    fn is_forbidden_global(name: &str) -> bool {
        matches!(
            name,
            "process"
                | "globalThis"
                | "window"
                | "document"
                | "navigator"
                | "global"
                | "Reflect"
                | "Proxy"
                | "WebAssembly"
                | "Atomics"
                | "SharedArrayBuffer"
        )
    }

    fn is_timer_fn(name: &str) -> bool {
        matches!(name, "setTimeout" | "setInterval")
    }

    fn expr_references_eval_indirect(expr: &Expr) -> bool {
        match expr {
            Expr::Ident(_) => false,
            Expr::Paren(paren) => Self::expr_references_eval_indirect(&paren.expr),
            Expr::Seq(seq) => seq.exprs.iter().any(|e| match e.as_ref() {
                Expr::Ident(ident) => ident.sym.as_ref() == JS_EVAL,
                _ => Self::expr_references_eval_indirect(e),
            }),
            Expr::Member(member) => {
                if let MemberProp::Ident(prop) = &member.prop {
                    prop.sym.as_ref() == JS_EVAL
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn callee_is_constructor_chain(expr: &Expr) -> bool {
        match expr {
            Expr::Member(member) => {
                match &member.prop {
                    MemberProp::Ident(prop) => {
                        if prop.sym.as_ref() == JS_CONSTRUCTOR {
                            return true;
                        }
                    }
                    MemberProp::Computed(computed) => {
                        if let Expr::Lit(swc_core::ecma::ast::Lit::Str(s)) = computed.expr.as_ref()
                            && s.value.as_ref() == JS_CONSTRUCTOR
                        {
                            return true;
                        }
                    }
                    _ => {}
                }
                Self::callee_is_constructor_chain(&member.obj)
            }
            Expr::Paren(paren) => Self::callee_is_constructor_chain(&paren.expr),
            _ => false,
        }
    }

    fn check_member_for_proto(&mut self, member: &MemberExpr) {
        match &member.prop {
            MemberProp::Ident(prop) => {
                let name = prop.sym.as_ref();
                if name == JS_PROTO {
                    self.add(
                        VIOLATION_PROTO_ACCESS,
                        "__proto__ property access is forbidden",
                        member.span.lo.0 as usize,
                    );
                }
                if name == JS_CONSTRUCTOR {
                    self.add(
                        VIOLATION_CONSTRUCTOR_ACCESS,
                        ".constructor property access is forbidden",
                        member.span.lo.0 as usize,
                    );
                }
            }
            MemberProp::Computed(computed) => {
                if let Expr::Lit(swc_core::ecma::ast::Lit::Str(s)) = computed.expr.as_ref() {
                    let val = s.value.as_ref();
                    if val == JS_PROTO {
                        self.add(
                            VIOLATION_PROTO_ACCESS,
                            "__proto__ property access (computed) is forbidden",
                            member.span.lo.0 as usize,
                        );
                    }
                    if val == JS_CONSTRUCTOR {
                        self.add(
                            VIOLATION_CONSTRUCTOR_ACCESS,
                            ".constructor property access (computed) is forbidden",
                            member.span.lo.0 as usize,
                        );
                    }
                }
            }
            _ => {}
        }

        if let Expr::Ident(obj_ident) = member.obj.as_ref() {
            let obj_name = obj_ident.sym.as_ref();
            if Self::is_forbidden_global(obj_name) {
                self.add(
                    "forbidden_global_access",
                    &format!("access to forbidden global '{}' is not allowed", obj_name),
                    member.span.lo.0 as usize,
                );
            }
        }
    }
}

impl Visit for SecurityVisitor {
    fn visit_call_expr(&mut self, node: &swc_core::ecma::ast::CallExpr) {
        match &node.callee {
            Callee::Expr(expr) => {
                if Self::expr_references_eval_indirect(expr) {
                    self.add(
                        VIOLATION_INDIRECT_EVAL,
                        "indirect eval() call is forbidden",
                        node.span.lo.0 as usize,
                    );
                }
                if Self::callee_is_constructor_chain(expr) {
                    self.add(
                        VIOLATION_CONSTRUCTOR_CHAIN_CALL,
                        ".constructor chain call is forbidden",
                        node.span.lo.0 as usize,
                    );
                }
                match expr.as_ref() {
                    Expr::Ident(ident) => {
                        let name = ident.sym.as_ref();
                        if name == JS_EVAL {
                            self.add(
                                VIOLATION_EVAL_CALL,
                                "eval() is forbidden",
                                ident.span.lo.0 as usize,
                            );
                        }
                        if name == JS_REQUIRE {
                            self.add(
                                VIOLATION_REQUIRE_CALL,
                                "require() is forbidden",
                                ident.span.lo.0 as usize,
                            );
                        }
                        if Self::is_timer_fn(name)
                            && !node.args.is_empty()
                            && let Expr::Lit(swc_core::ecma::ast::Lit::Str(_)) =
                                node.args[0].expr.as_ref()
                        {
                            self.add(
                                VIOLATION_TIMER_STRING_ARG,
                                &format!(
                                    "{}() with string argument is forbidden (evaluated as code)",
                                    name
                                ),
                                ident.span.lo.0 as usize,
                            );
                        }
                    }
                    Expr::Member(member) => {
                        self.check_member_for_proto(member);
                        if let Expr::Ident(obj_ident) = member.obj.as_ref() {
                            let obj_name = obj_ident.sym.as_ref();
                            if Self::is_forbidden_global(obj_name) {
                                self.add(
                                    VIOLATION_FORBIDDEN_GLOBAL_CALL,
                                    &format!(
                                        "calling methods on forbidden global '{}' is not allowed",
                                        obj_name
                                    ),
                                    member.span.lo.0 as usize,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            Callee::Import(_) => {
                self.add(
                    VIOLATION_DYNAMIC_IMPORT,
                    "dynamic import() is forbidden",
                    node.span.lo.0 as usize,
                );
            }
            _ => {}
        }

        for arg in &node.args {
            arg.visit_with(self);
        }
    }

    fn visit_new_expr(&mut self, node: &NewExpr) {
        let is_function = match node.callee.as_ref() {
            Expr::Ident(ident) => ident.sym.as_ref() == JS_FUNCTION,
            _ => false,
        };
        if is_function {
            self.add(
                VIOLATION_FUNCTION_CONSTRUCTOR,
                "new Function() constructor is forbidden",
                node.span.lo.0 as usize,
            );
        }
        if let Some(args) = &node.args {
            for arg in args {
                arg.visit_with(self);
            }
        }
        node.callee.visit_with(self);
    }

    fn visit_member_expr(&mut self, node: &MemberExpr) {
        self.check_member_for_proto(node);
        node.obj.visit_with(self);
        if let MemberProp::Computed(computed) = &node.prop {
            computed.visit_with(self);
        }
    }

    fn visit_with_stmt(&mut self, node: &WithStmt) {
        self.add(
            VIOLATION_WITH_STATEMENT,
            "with statement is forbidden",
            node.span.lo.0 as usize,
        );
        node.body.visit_with(self);
    }

    fn visit_expr(&mut self, node: &Expr) {
        match node {
            Expr::Ident(ident) => {
                let name = ident.sym.as_ref();
                if Self::is_forbidden_global(name) {
                    self.add(
                        VIOLATION_FORBIDDEN_GLOBAL_ACCESS,
                        &format!("access to forbidden global '{}' is not allowed", name),
                        ident.span.lo.0 as usize,
                    );
                }
            }
            Expr::MetaProp(meta) => {
                if matches!(meta.kind, MetaPropKind::ImportMeta) {
                    self.add(
                        VIOLATION_IMPORT_META,
                        "import.meta is forbidden",
                        meta.span.lo.0 as usize,
                    );
                }
            }
            _ => {}
        }
        node.visit_children_with(self);
    }
}

pub fn validate_ast(ts_code: &str) -> Result<Vec<AstViolation>> {
    validate_ast_with_syntax(
        ts_code,
        Syntax::Typescript(TsSyntax {
            tsx: false,
            decorators: true,
            dts: false,
            no_early_errors: false,
            disallow_ambiguous_jsx_like: false,
        }),
        "TypeScript",
    )
}

pub fn validate_js_ast(js_code: &str) -> Result<Vec<AstViolation>> {
    validate_ast_with_syntax(js_code, Syntax::Es(Default::default()), "JavaScript")
}

fn validate_ast_with_syntax(code: &str, syntax: Syntax, label: &str) -> Result<Vec<AstViolation>> {
    let cm: Rc<SourceMap> = Rc::new(SourceMap::default());
    let source = code.to_string();

    GLOBALS.set(&Default::default(), || {
        let fm = cm.new_source_file(
            FileName::Custom(format!("iepl-validate-{}", label.to_lowercase())).into(),
            code.to_string(),
        );

        let lexer = Lexer::new(
            syntax,
            Default::default(),
            StringInput::from(fm.as_ref()),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        let program = parser
            .parse_program()
            .map_err(|e| anyhow!("{} parse error: {:?}", label, e))?;

        let mut visitor = SecurityVisitor::new(source);
        program.visit_with(&mut visitor);

        Ok(visitor.violations)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn clean_code_no_violations() -> Result<()> {
        let code = r#"const x: number = 42; console.log(x);"#;
        let violations = validate_ast(code)?;
        assert!(violations.is_empty());
        Ok(())
    }

    #[test]
    fn detects_eval() -> Result<()> {
        let code = r#"eval("console.log(1)")"#;
        let violations = validate_ast(code)?;
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, VIOLATION_EVAL_CALL);
        Ok(())
    }

    #[test]
    fn detects_function_constructor() -> Result<()> {
        let code = r#"const f = new Function("return 1")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FUNCTION_CONSTRUCTOR),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_dynamic_import() -> Result<()> {
        let code = r#"import("some-module")"#;
        let violations = validate_ast(code)?;
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, VIOLATION_DYNAMIC_IMPORT);
        Ok(())
    }

    #[test]
    fn detects_require() -> Result<()> {
        let code = r#"require("fs")"#;
        let violations = validate_ast(code)?;
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, VIOLATION_REQUIRE_CALL);
        Ok(())
    }

    #[test]
    fn detects_process_global() -> Result<()> {
        let code = r#"const env = process.env"#;
        let violations = validate_ast(code)?;
        assert!(!violations.is_empty());
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FORBIDDEN_GLOBAL_ACCESS)
        );
        Ok(())
    }

    #[test]
    fn detects_global_this() -> Result<()> {
        let code = r#"globalThis.foo = 1"#;
        let violations = validate_ast(code)?;
        assert!(!violations.is_empty());
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FORBIDDEN_GLOBAL_ACCESS)
        );
        Ok(())
    }

    #[test]
    fn detects_window_access() -> Result<()> {
        let code = r#"window.location.href"#;
        let violations = validate_ast(code)?;
        assert!(!violations.is_empty());
        Ok(())
    }

    #[test]
    fn detects_document_access() -> Result<()> {
        let code = r#"document.getElementById("x")"#;
        let violations = validate_ast(code)?;
        assert!(!violations.is_empty());
        Ok(())
    }

    #[test]
    fn detects_proto_access() -> Result<()> {
        let code = r#"const p = obj.__proto__"#;
        let violations = validate_ast(code)?;
        assert!(violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS));
        Ok(())
    }

    #[test]
    fn detects_computed_proto_access() -> Result<()> {
        let code = r#"const p = obj["__proto__"]"#;
        let violations = validate_ast(code)?;
        assert!(violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS));
        Ok(())
    }

    #[test]
    fn detects_constructor_on_object_literal() -> Result<()> {
        let code = r#"({}).constructor"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS)
        );
        Ok(())
    }

    #[test]
    fn allows_tool_call_style() -> Result<()> {
        let code = r#"import { file_read } from 'kalos'; const r = file_read({path: "x"}); import { report } from 'hubris'; report({text: r.data.content});"#;
        let violations = validate_ast(code)?;
        assert!(violations.is_empty());
        Ok(())
    }

    #[test]
    fn multiple_violations() -> Result<()> {
        let code = r#"
            eval("x");
            require("fs");
            process.exit(1);
        "#;
        let violations = validate_ast(code)?;
        assert!(violations.len() >= 3);
        Ok(())
    }

    #[test]
    fn detects_import_meta() -> Result<()> {
        let code = r#"const url = import.meta.url"#;
        let violations = validate_ast(code)?;
        assert!(violations.iter().any(|v| v.kind == VIOLATION_IMPORT_META));
        Ok(())
    }

    #[test]
    fn detects_indirect_eval_comma() -> Result<()> {
        let code = r#"(1, eval)("console.log(1)")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_INDIRECT_EVAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_constructor_chain() -> Result<()> {
        let code = r#"const f = (function(){}).constructor("return 1")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_CHAIN_CALL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_reflect_access() -> Result<()> {
        let code = r#"Reflect.apply(fn, this, [])"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FORBIDDEN_GLOBAL_CALL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_any_constructor_access() -> Result<()> {
        let code = r#"[].constructor.constructor("return 1")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_CHAIN_CALL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_settimeout_string_arg() -> Result<()> {
        let code = r#"setTimeout("console.log(1)", 100)"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_TIMER_STRING_ARG),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_setinterval_string_arg() -> Result<()> {
        let code = r#"setInterval("console.log(1)", 100)"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_TIMER_STRING_ARG),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn allows_settimeout_function_arg() -> Result<()> {
        let code = r#"setTimeout(() => console.log(1), 100)"#;
        let violations = validate_ast(code)?;
        assert!(
            !violations
                .iter()
                .any(|v| v.kind == VIOLATION_TIMER_STRING_ARG),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_webassembly_access() -> Result<()> {
        let code = r#"WebAssembly.instantiate(buf)"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FORBIDDEN_GLOBAL_CALL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_atomics_access() -> Result<()> {
        let code = r#"Atomics.load(arr, 0)"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_FORBIDDEN_GLOBAL_CALL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_shared_array_buffer_access() -> Result<()> {
        let code = r#"const buf = new SharedArrayBuffer(1024)"#;
        let violations = validate_ast(code)?;
        assert!(!violations.is_empty(), "got: {:?}", violations);
        Ok(())
    }

    #[test]
    fn line_col_multiline() -> Result<()> {
        let code = "line1;\nline2;\neval(\"x\")";
        let violations = validate_ast(code)?;
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, 3);
        assert_eq!(violations[0].column, 1);
        Ok(())
    }

    #[test]
    fn line_col_single_line() -> Result<()> {
        let code = r#"const x = eval("1")"#;
        let violations = validate_ast(code)?;
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, 1);
        assert!(violations[0].column > 1);
        Ok(())
    }
}
