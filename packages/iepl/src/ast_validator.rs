use anyhow::{Result, anyhow};
use std::{collections::HashSet, rc::Rc};

use swc_core::{
    common::{FileName, GLOBALS, SourceMap},
    ecma::{
        ast::{
            AssignExpr, AssignOp, AssignTarget, BinExpr, BinaryOp, Callee, Expr, Lit, MemberExpr,
            MemberProp, MetaPropKind, NewExpr, ObjectLit, ObjectPat, ObjectPatProp, Pat, Prop,
            PropName, PropOrSpread, SimpleAssignTarget, Tpl, VarDeclarator, WithStmt,
        },
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
    eval_aliases: HashSet<String>,
}

/// Pre-pass that collects bindings assigned the value of `eval` (directly,
/// through parentheses/sequences, or through member access like `window.eval`),
/// so calls through aliases can be rejected regardless of declaration order.
struct EvalAliasCollector {
    candidates: Vec<(String, EvalAliasRef)>,
}

#[derive(Clone)]
enum EvalAliasRef {
    Direct,
    Named(String),
    Member,
    Paren(Box<EvalAliasRef>),
    Seq(Vec<EvalAliasRef>),
}

impl EvalAliasRef {
    fn from_expr(expr: &Expr) -> Option<Self> {
        match expr {
            Expr::Ident(ident) => {
                let name = ident.sym.as_ref();
                if name == JS_EVAL {
                    Some(Self::Direct)
                } else {
                    Some(Self::Named(name.to_string()))
                }
            }
            Expr::Paren(paren) => {
                Self::from_expr(&paren.expr).map(|inner| Self::Paren(Box::new(inner)))
            }
            Expr::Seq(seq) => {
                let items: Vec<EvalAliasRef> = seq
                    .exprs
                    .iter()
                    .filter_map(|e| Self::from_expr(e))
                    .collect();
                Some(Self::Seq(items))
            }
            Expr::Member(member) => {
                if matches!(&member.prop, MemberProp::Ident(prop) if prop.sym.as_ref() == JS_EVAL) {
                    Some(Self::Member)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn references(&self, known_aliases: &HashSet<String>) -> bool {
        match self {
            Self::Direct | Self::Member => true,
            Self::Named(name) => known_aliases.contains(name),
            Self::Paren(inner) => inner.references(known_aliases),
            Self::Seq(items) => items.iter().any(|item| item.references(known_aliases)),
        }
    }
}

impl EvalAliasCollector {
    fn new() -> Self {
        Self {
            candidates: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, init: &Expr) {
        if let Some(reference) = EvalAliasRef::from_expr(init) {
            self.candidates.push((name.to_string(), reference));
        }
    }

    fn resolve(&self) -> HashSet<String> {
        let mut aliases: HashSet<String> = HashSet::new();
        loop {
            let mut added = false;
            for (name, reference) in &self.candidates {
                if !aliases.contains(name) && reference.references(&aliases) {
                    aliases.insert(name.clone());
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        aliases
    }
}

impl Visit for EvalAliasCollector {
    fn visit_var_declarator(&mut self, node: &VarDeclarator) {
        if let (Pat::Ident(binding), Some(init)) = (&node.name, &node.init) {
            self.record(&binding.id.sym, init);
        }
        node.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, node: &AssignExpr) {
        if node.op == AssignOp::Assign
            && let AssignTarget::Simple(SimpleAssignTarget::Ident(binding)) = &node.left
        {
            self.record(&binding.id.sym, &node.right);
        }
        node.visit_children_with(self);
    }
}

impl SecurityVisitor {
    fn with_eval_aliases(source: String, eval_aliases: HashSet<String>) -> Self {
        Self {
            violations: Vec::new(),
            source,
            eval_aliases,
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

    /// Constructors whose first argument is an allocation size.
    fn is_memory_allocator(name: &str) -> bool {
        matches!(
            name,
            "Array"
                | "ArrayBuffer"
                | "DataView"
                | "Int8Array"
                | "Uint8Array"
                | "Uint8ClampedArray"
                | "Int16Array"
                | "Uint16Array"
                | "Int32Array"
                | "Uint32Array"
                | "Float32Array"
                | "Float64Array"
                | "BigInt64Array"
                | "BigUint64Array"
        )
    }

    fn numeric_literal_value(expr: &Expr) -> Option<f64> {
        match expr {
            Expr::Lit(swc_core::ecma::ast::Lit::Num(n)) => Some(n.value),
            Expr::Paren(paren) => Self::numeric_literal_value(&paren.expr),
            _ => None,
        }
    }

    fn is_memory_bomb_size(value: f64) -> bool {
        value > MEMORY_BOMB_LITERAL_THRESHOLD
    }

    fn check_allocation_size(
        &mut self,
        callee_name: &str,
        size: f64,
        span: swc_core::common::Span,
    ) {
        if Self::is_memory_bomb_size(size) {
            self.add(
                VIOLATION_MEMORY_BOMB_LITERAL,
                &format!(
                    "{}() with a literal size exceeding the memory-bomb threshold \
                     ({:.0} elements) is forbidden",
                    callee_name, MEMORY_BOMB_LITERAL_THRESHOLD
                ),
                span.lo.0 as usize,
            );
        }
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

    fn expr_references_function_constructor(expr: &Expr) -> bool {
        match expr {
            Expr::Ident(ident) => ident.sym.as_ref() == JS_FUNCTION,
            Expr::Paren(paren) => Self::expr_references_function_constructor(&paren.expr),
            Expr::Seq(seq) => seq
                .exprs
                .iter()
                .any(|e| Self::expr_references_function_constructor(e)),
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

    /// Statically folds an expression to its string value when possible
    /// (string literals, `+` concatenation of foldable operands, and template
    /// literals whose interpolations fold). Used to defeat `["con"+"structor"]`
    /// style computed-key smuggling.
    fn const_fold_string(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Lit(Lit::Str(s)) => Some(s.value.to_string()),
            Expr::Paren(paren) => Self::const_fold_string(&paren.expr),
            Expr::Bin(BinExpr {
                op: BinaryOp::Add,
                left,
                right,
                ..
            }) => {
                let left = Self::const_fold_string(left)?;
                let right = Self::const_fold_string(right)?;
                Some(format!("{}{}", left, right))
            }
            Expr::Tpl(Tpl { quasis, exprs, .. }) => {
                let mut out = String::new();
                for (i, quasi) in quasis.iter().enumerate() {
                    out.push_str(
                        quasi
                            .cooked
                            .as_ref()
                            .map(|c| c.as_ref())
                            .unwrap_or(quasi.raw.as_ref()),
                    );
                    if let Some(expr) = exprs.get(i) {
                        out.push_str(&Self::const_fold_string(expr)?);
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn check_folded_key(
        &mut self,
        folded: &str,
        node_span: &swc_core::common::Span,
        context: &str,
    ) {
        if folded == JS_PROTO {
            self.add(
                VIOLATION_PROTO_ACCESS,
                &format!("__proto__ {} is forbidden", context),
                node_span.lo.0 as usize,
            );
        }
        if folded == JS_CONSTRUCTOR {
            self.add(
                VIOLATION_CONSTRUCTOR_ACCESS,
                &format!(".constructor {} is forbidden", context),
                node_span.lo.0 as usize,
            );
        }
    }

    /// Checks object literal / destructuring pattern keys. Literal `__proto__`
    /// keys in object literals set the prototype (prototype pollution);
    /// destructuring `constructor`/`__proto__` keys extract the properties the
    /// validator otherwise blocks via member access.
    fn check_prop_name(
        &mut self,
        key: &PropName,
        node_span: &swc_core::common::Span,
        context: &str,
        allow_plain_constructor: bool,
    ) {
        match key {
            PropName::Ident(ident) => {
                let name = ident.sym.as_ref();
                if name == JS_PROTO {
                    self.check_folded_key(JS_PROTO, node_span, context);
                } else if !allow_plain_constructor && name == JS_CONSTRUCTOR {
                    self.check_folded_key(JS_CONSTRUCTOR, node_span, context);
                }
            }
            PropName::Str(s) => {
                let val = s.value.as_ref();
                if val == JS_PROTO {
                    self.check_folded_key(JS_PROTO, node_span, context);
                } else if !allow_plain_constructor && val == JS_CONSTRUCTOR {
                    self.check_folded_key(JS_CONSTRUCTOR, node_span, context);
                }
            }
            PropName::Computed(computed) => {
                if let Some(folded) = Self::const_fold_string(&computed.expr) {
                    self.check_folded_key(&folded, node_span, context);
                }
            }
            _ => {}
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
                if let Some(folded) = Self::const_fold_string(&computed.expr) {
                    self.check_folded_key(&folded, &member.span, "property access (computed)");
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
                if Self::expr_references_function_constructor(expr) {
                    self.add(
                        VIOLATION_FUNCTION_CONSTRUCTOR,
                        "Function() constructor call is forbidden",
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
                        if self.eval_aliases.contains(name) {
                            self.add(
                                VIOLATION_EVAL_ALIAS,
                                "call through eval() alias is forbidden",
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
                        if name == "Array"
                            && let Some(size) = node
                                .args
                                .first()
                                .and_then(|a| Self::numeric_literal_value(&a.expr))
                        {
                            self.check_allocation_size("Array", size, node.span);
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
                        if let MemberProp::Ident(prop) = &member.prop
                            && prop.sym.as_ref() == "repeat"
                            && let Expr::Lit(swc_core::ecma::ast::Lit::Str(_)) = member.obj.as_ref()
                            && let Some(size) = node
                                .args
                                .first()
                                .and_then(|a| Self::numeric_literal_value(&a.expr))
                        {
                            self.check_allocation_size("String.repeat", size, node.span);
                        }
                    }
                    Expr::Call(_) => {
                        // A call used as the callee of another call (e.g.
                        // `Function("return 1")()`) is never visited by the
                        // default traversal, so recurse into it explicitly.
                        expr.visit_with(self);
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
        if let Expr::Ident(ident) = node.callee.as_ref()
            && Self::is_memory_allocator(ident.sym.as_ref())
            && let Some(args) = &node.args
            && let Some(size) = args
                .first()
                .and_then(|a| Self::numeric_literal_value(&a.expr))
        {
            self.check_allocation_size(&ident.sym, size, node.span);
        }
        if let Some(args) = &node.args {
            for arg in args {
                arg.visit_with(self);
            }
        }
        node.callee.visit_with(self);
    }

    fn visit_object_lit(&mut self, node: &ObjectLit) {
        for prop in &node.props {
            if let PropOrSpread::Prop(prop) = prop
                && let Prop::KeyValue(kv) = prop.as_ref()
            {
                let context = if matches!(kv.key, PropName::Computed(_)) {
                    "key (computed)"
                } else {
                    "key"
                };
                self.check_prop_name(&kv.key, &node.span, context, true);
            }
        }
        node.visit_children_with(self);
    }

    fn visit_object_pat(&mut self, node: &ObjectPat) {
        for prop in &node.props {
            match prop {
                ObjectPatProp::KeyValue(kv) => {
                    let context = if matches!(kv.key, PropName::Computed(_)) {
                        "destructuring key (computed)"
                    } else {
                        "destructuring key"
                    };
                    self.check_prop_name(&kv.key, &node.span, context, false);
                }
                ObjectPatProp::Assign(assign) => {
                    let name = assign.key.id.sym.as_ref();
                    if name == JS_PROTO {
                        self.check_folded_key(JS_PROTO, &node.span, "destructuring key");
                    } else if name == JS_CONSTRUCTOR {
                        self.check_folded_key(JS_CONSTRUCTOR, &node.span, "destructuring key");
                    }
                }
                _ => {}
            }
        }
        node.visit_children_with(self);
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

        let mut visitor =
            SecurityVisitor::with_eval_aliases(source, collect_eval_aliases(&program));
        program.visit_with(&mut visitor);

        Ok(visitor.violations)
    })
}

/// First pass that resolves all bindings whose value is `eval` (including
/// chains like `const a = eval; const b = a;`) regardless of source order, so
/// calls through aliases are rejected even when the call site precedes the
/// alias declaration textually (e.g. inside a function body).
fn collect_eval_aliases(program: &swc_core::ecma::ast::Program) -> HashSet<String> {
    let mut collector = EvalAliasCollector::new();
    program.visit_with(&mut collector);
    collector.resolve()
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
    fn rejects_string_repeat_memory_bomb() -> Result<()> {
        let code = r#"const s = "x".repeat(1000000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn rejects_new_array_memory_bomb() -> Result<()> {
        let code = r#"const a = new Array(100000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn rejects_array_call_memory_bomb() -> Result<()> {
        let code = r#"const a = Array(100000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn rejects_typed_array_memory_bomb() -> Result<()> {
        let code = r#"const buf = new Uint8Array(100000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn rejects_array_buffer_memory_bomb() -> Result<()> {
        let code = r#"const buf = new ArrayBuffer(100000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn allows_small_allocation_literals() -> Result<()> {
        let code = r#"
            const s = "x".repeat(100);
            const a = new Array(100000);
            const b = new Uint8Array(1024);
            const c = new ArrayBuffer(4096);
            const d = new Float64Array(64);
        "#;
        let violations = validate_ast(code)?;
        assert!(
            violations.is_empty(),
            "small literals must not trigger memory-bomb heuristic: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn allows_string_repeat_threshold_boundary() -> Result<()> {
        let code = r#"const s = "x".repeat(10000000);"#;
        let violations = validate_ast(code)?;
        assert!(
            !violations
                .iter()
                .any(|v| v.kind == VIOLATION_MEMORY_BOMB_LITERAL),
            "exactly 1e7 is below the strict threshold: {:?}",
            violations
        );
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
    fn detects_eval_alias_call() -> Result<()> {
        let code = r#"const e = eval; e("console.log(1)")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_EVAL_ALIAS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_eval_alias_via_assignment() -> Result<()> {
        let code = r#"let e; e = eval; e("console.log(1)")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_EVAL_ALIAS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_eval_alias_chain() -> Result<()> {
        let code = r#"const a = eval; const b = a; b("console.log(1)")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_EVAL_ALIAS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_eval_alias_in_function_before_declaration() -> Result<()> {
        let code = r#"
            function f() { e("console.log(1)") }
            var e = eval;
        "#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_EVAL_ALIAS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_computed_concat_constructor() -> Result<()> {
        let code = r#"const c = obj["con" + "structor"]"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        let code = r#"obj["con" + "structor"]("return 1")"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_computed_concat_proto() -> Result<()> {
        let code = r#"const p = obj["__pro" + "to__"]"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_computed_template_constructor() -> Result<()> {
        let code = r#"const c = obj[`con${"structor"}`]"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_object_literal_computed_proto_key() -> Result<()> {
        let code = r#"const o = {["__proto__"]: x}"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_object_literal_plain_proto_key() -> Result<()> {
        let code = r#"const o = {__proto__: null}"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_object_literal_computed_constructor_key() -> Result<()> {
        let code = r#"const o = {["constructor"]: x}"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn allows_object_literal_plain_constructor_key() -> Result<()> {
        let code = r#"const o = {constructor: () => 1};"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .all(|v| v.kind != VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_destructuring_computed_constructor() -> Result<()> {
        let code = r#"const {["constructor"]: c} = o"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_destructuring_computed_proto() -> Result<()> {
        let code = r#"const {["__proto__"]: p} = o"#;
        let violations = validate_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_PROTO_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_destructuring_plain_constructor() -> Result<()> {
        let code = r#"const {constructor: c} = o"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_destructuring_shorthand_constructor() -> Result<()> {
        let code = r#"const {constructor} = o"#;
        let violations = validate_ast(code)?;
        assert!(
            violations
                .iter()
                .any(|v| v.kind == VIOLATION_CONSTRUCTOR_ACCESS),
            "got: {:?}",
            violations
        );
        Ok(())
    }

    #[test]
    fn detects_function_call_constructor() -> Result<()> {
        let code = r#"Function("return 1")()"#;
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
    fn detects_eval_alias_in_js_syntax() -> Result<()> {
        let code = r#"const e = eval; e("console.log(1)")"#;
        let violations = validate_js_ast(code)?;
        assert!(
            violations.iter().any(|v| v.kind == VIOLATION_EVAL_ALIAS),
            "got: {:?}",
            violations
        );
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
