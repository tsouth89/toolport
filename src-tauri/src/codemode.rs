//! Server-side tool orchestration ("code mode"): run ONE agent-submitted script that
//! calls multiple downstream tools, loops, and branches, and returns a single aggregated
//! value. This is the results-layer twin of lazy discovery: lazy discovery collapses N
//! tool *definitions* to a handful of meta-tools; code mode collapses N tool *calls +
//! results* to one `run_script` round-trip, so the intermediate results never land in the
//! model's context.
//!
//! The engine is [`boa_engine`], a pure-Rust JS interpreter, so this adds no C toolchain
//! or FFI to the build. Because Toolport is single-user and local, the agent is already
//! trusted and the servers already run on the host: the sandbox's job is round-trip and
//! token reduction, NOT a security boundary. It still fails closed on resource limits so a
//! runaway or buggy script can't wedge the gateway.
//!
//! The one capability a script gets is `toolport.call(name, args)`, a synchronous binding
//! that routes a single downstream call through the caller-supplied closure — which the
//! gateway wires to the SAME path a direct `toolport_call_tool` takes (per-client scope,
//! human approval, result shaping), so a script never widens what the client could already
//! reach. Limits: a cap on the number of downstream calls, a wall-clock deadline (checked
//! at each call), and boa's own loop-iteration / recursion caps for pure-JS runaway.

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use boa_engine::{
    js_string, Context, JsError, JsNativeError, JsValue, NativeFunction, Source,
};
use boa_engine::property::Attribute;
use boa_gc::{Finalize, Trace};
use serde_json::{json, Value};

/// Resource limits for one script run. All are fail-closed: exceeding any of them aborts
/// the script with an error result the agent can read and recover from.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Max number of `toolport.call()` invocations. Bounds fan-out and downstream load.
    pub max_calls: usize,
    /// Wall-clock budget for the whole run, checked at each `toolport.call()`.
    pub wall_clock: Duration,
    /// Max total loop iterations across the script (boa runtime limit); bounds a pure-JS
    /// `while(true){}` that never calls a tool.
    pub loop_iteration_limit: u64,
    /// Max recursion depth (boa runtime limit).
    pub recursion_limit: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_calls: 64,
            wall_clock: Duration::from_secs(60),
            loop_iteration_limit: 10_000_000,
            recursion_limit: 400,
        }
    }
}

/// The outcome of running a script.
#[derive(Debug, Clone)]
pub struct ScriptOutcome {
    /// The script's return value as JSON (`null` if it returned nothing). Meaningful only
    /// when `error` is `None`.
    pub value: Value,
    /// How many `toolport.call()` invocations the script actually made — used to account
    /// round-trips saved (calls - 1) and to report fan-out.
    pub calls: usize,
    /// `Some(message)` if the script threw, hit a limit, or failed to compile. Fail-closed:
    /// the caller surfaces this to the agent as an error result.
    pub error: Option<String>,
}

/// Host state shared with the `__toolport_call` native function. Holds no JS/GC references,
/// so its `Trace` impl is empty (sound: nothing here points into the boa heap).
struct HostState {
    /// The downstream call binding: `(tool_name, arguments) -> result`. Boxed so the caller
    /// can supply any closure; `Rc<RefCell>` because boa native functions are `Fn`, not
    /// `FnMut`, and the closure is single-threaded (boa `Context` is `!Send`).
    call: Rc<dyn Fn(&str, Value) -> Value>,
    /// Shared with the run so the count survives after the closure is moved into boa.
    calls_made: Rc<Cell<usize>>,
    max_calls: usize,
    deadline: Instant,
}

impl Finalize for HostState {}
// SAFETY: HostState holds only Rust-owned data (an `Rc<dyn Fn>`, counters, an `Instant`),
// never a boa `Gc`/`JsValue`, so there is nothing for the collector to trace: every method
// is a sound no-op.
unsafe impl Trace for HostState {
    unsafe fn trace(&self, _tracer: &mut boa_gc::Tracer) {}
    unsafe fn trace_non_roots(&self) {}
    fn run_finalizer(&self) {}
}

/// The JS prelude installed before the user script. Wraps the raw `__toolport_call` host
/// binding (which speaks JSON strings) in an ergonomic `toolport.call(name, args)` that
/// takes/returns real JS values, and exposes the injected `data` payload.
const PRELUDE: &str = r#"
globalThis.toolport = {
    call: function (name, args) {
        var payload = (args === undefined || args === null) ? {} : args;
        return JSON.parse(__toolport_call(String(name), JSON.stringify(payload)));
    },
};
"#;

/// Run `script` with `data` available as a global `data` object, giving it `toolport.call`
/// bound to `call`. Returns one aggregated [`ScriptOutcome`]; intermediate call results are
/// never surfaced. Synchronous: `await`/Promises are not driven in v1 (a script that needs
/// concurrency is a follow-up), so scripts should call tools sequentially.
///
/// `call` must be `'static` (the gateway builds it from `Arc`-cloned handles). It is invoked
/// once per `toolport.call()`; whatever it returns becomes that call's JS result.
pub fn run_script(
    script: &str,
    data: Value,
    call: Rc<dyn Fn(&str, Value) -> Value>,
    limits: Limits,
) -> ScriptOutcome {
    let calls_made = Rc::new(Cell::new(0usize));
    let mut context = Context::default();

    // Pure-JS runaway guards (a script that loops/recurses forever without calling a tool).
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(limits.loop_iteration_limit);
    context
        .runtime_limits_mut()
        .set_recursion_limit(limits.recursion_limit);

    let state = HostState {
        call,
        calls_made: calls_made.clone(),
        max_calls: limits.max_calls,
        deadline: Instant::now() + limits.wall_clock,
    };

    // The raw host binding: (nameString, argsJsonString) -> resultJsonString. Enforces the
    // call budget and wall-clock deadline before every downstream call, fail-closed.
    let native = NativeFunction::from_copy_closure_with_captures(
        |_this: &JsValue, args: &[JsValue], state: &HostState, _ctx: &mut Context| {
            if state.calls_made.get() >= state.max_calls {
                return Err(JsError::from_native(JsNativeError::error().with_message(
                    format!("toolport.call budget exceeded ({} calls)", state.max_calls),
                )));
            }
            if Instant::now() >= state.deadline {
                return Err(JsError::from_native(
                    JsNativeError::error().with_message("toolport script wall-clock deadline exceeded"),
                ));
            }
            let name = args
                .first()
                .and_then(JsValue::as_string)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            let args_json = args
                .get(1)
                .and_then(JsValue::as_string)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "{}".to_string());
            let parsed: Value = serde_json::from_str(&args_json).unwrap_or(Value::Null);

            state.calls_made.set(state.calls_made.get() + 1);
            let result = (state.call)(&name, parsed);

            let result_str = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string());
            Ok(JsValue::from(js_string!(result_str)))
        },
        state,
    );

    if let Err(e) = context.register_global_callable(js_string!("__toolport_call"), 2, native) {
        return fail(&mut context, calls_made.get(), e);
    }

    // Inject `data` as a global before the prelude/script run.
    match JsValue::from_json(&data, &mut context) {
        Ok(v) => {
            if let Err(e) =
                context.register_global_property(js_string!("data"), v, Attribute::all())
            {
                return fail(&mut context, calls_made.get(), e);
            }
        }
        Err(e) => return fail(&mut context, calls_made.get(), e),
    }

    if let Err(e) = context.eval(Source::from_bytes(PRELUDE)) {
        return fail(&mut context, calls_made.get(), e);
    }

    // Wrap the user script in an IIFE so a top-level `return` works and the whole thing is
    // one expression whose value is the script's result.
    let wrapped = format!("(function () {{\n{script}\n}})()");
    match context.eval(Source::from_bytes(wrapped.as_bytes())) {
        Ok(v) => {
            let value = v.to_json(&mut context).ok().flatten().unwrap_or(Value::Null);
            ScriptOutcome {
                value,
                calls: calls_made.get(),
                error: None,
            }
        }
        Err(e) => fail(&mut context, calls_made.get(), e),
    }
}

/// Build a fail-closed outcome from a boa error, rendering it to a readable message.
/// Uses the error's `Display` rather than `to_opaque` on purpose: boa's uncatchable
/// runtime-limit errors (loop/recursion caps) panic when converted to an opaque JS value,
/// and `Display` yields a usable message (`Uncaught Error: ...`, `RuntimeLimit: ...`) for
/// every error kind.
fn fail(_context: &mut Context, calls: usize, err: JsError) -> ScriptOutcome {
    ScriptOutcome {
        value: json!(null),
        calls,
        error: Some(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A call binding that records the calls it saw and echoes a canned reply per tool.
    fn recording_call(
        log: Rc<RefCell<Vec<(String, Value)>>>,
    ) -> Rc<dyn Fn(&str, Value) -> Value> {
        Rc::new(move |name: &str, args: Value| {
            log.borrow_mut().push((name.to_string(), args.clone()));
            json!({ "echo": name, "args": args })
        })
    }

    #[test]
    fn runs_a_plain_script_and_returns_its_value() {
        let call = Rc::new(|_: &str, _: Value| Value::Null);
        let out = run_script("return 1 + 2;", json!({}), call, Limits::default());
        assert_eq!(out.error, None);
        assert_eq!(out.value, json!(3));
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn toolport_call_reaches_the_binding_and_data_is_injected() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let call = recording_call(log.clone());
        let script = r#"
            var out = [];
            for (var i = 0; i < data.ids.length; i++) {
                var r = toolport.call("lookup", { id: data.ids[i] });
                out.push(r.args.id);
            }
            return out;
        "#;
        let out = run_script(script, json!({ "ids": [10, 20, 30] }), call, Limits::default());
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!([10, 20, 30]));
        assert_eq!(out.calls, 3);
        assert_eq!(log.borrow().len(), 3);
        assert_eq!(log.borrow()[0].0, "lookup");
        assert_eq!(log.borrow()[1].1, json!({ "id": 20 }));
    }

    #[test]
    fn call_budget_is_enforced() {
        let call = Rc::new(|_: &str, _: Value| json!({}));
        let limits = Limits {
            max_calls: 2,
            ..Limits::default()
        };
        let out = run_script(
            "for (var i = 0; i < 10; i++) { toolport.call('t', {}); } return 'done';",
            json!({}),
            call,
            limits,
        );
        // Fail-closed: it made exactly the budgeted calls, then errored instead of finishing.
        assert_eq!(out.calls, 2);
        assert_ne!(out.error, None);
        assert!(out.error.unwrap().contains("budget"));
    }

    #[test]
    fn loop_limit_stops_pure_js_runaway() {
        let call = Rc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            loop_iteration_limit: 1000,
            ..Limits::default()
        };
        let out = run_script("while (true) {} return 1;", json!({}), call, limits);
        assert_ne!(out.error, None, "an infinite loop must be stopped");
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn a_thrown_error_is_reported_not_panicked() {
        let call = Rc::new(|_: &str, _: Value| Value::Null);
        let out = run_script("throw new Error('boom');", json!({}), call, Limits::default());
        assert!(out.error.unwrap().contains("boom"));
    }

    #[test]
    fn syntax_error_fails_closed() {
        let call = Rc::new(|_: &str, _: Value| Value::Null);
        let out = run_script("this is not valid )(", json!({}), call, Limits::default());
        assert_ne!(out.error, None);
        assert_eq!(out.calls, 0);
    }
}
