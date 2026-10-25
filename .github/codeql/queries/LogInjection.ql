/**
 * @name Log entries created from user input
 * @description Building log entries from user-controlled sources is vulnerable to
 *              insertion of forged log entries by a malicious user. This is the stock
 *              go/log-injection query, except that the arguments of log/slog calls are
 *              not sinks while every slog handler of the program is a standard library
 *              handler (see slogHandlersAreStandard).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id previewd/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import go
import semmle.go.security.LogInjection

/** A source file of the program, as opposed to a test. */
predicate isProgramFile(File f) { not f.getBaseName().regexpMatch(".*_test\\.go") }

/** A call that builds one of the two standard library slog handlers. */
predicate isStandardHandler(DataFlow::CallNode call) {
  call.getTarget().hasQualifiedName("log/slog", ["NewJSONHandler", "NewTextHandler"])
}

/**
 * A call to slog.New in the program whose handler does not come, within the
 * function, from a standard library handler.
 */
predicate foreignHandlerLogger(DataFlow::CallNode call) {
  call.getTarget().hasQualifiedName("log/slog", "New") and
  isProgramFile(call.getFile()) and
  not exists(DataFlow::CallNode handler |
    isStandardHandler(handler) and
    DataFlow::localFlow(handler.getResult(), call.getArgument(0))
  )
}

/** A type declared in the program that is, or points to, a slog.Handler. */
predicate customHandlerType(DefinedType t) {
  isProgramFile(t.getEntity().(DeclaredTypeEntity).getSpec().getFile()) and
  (
    t.implements("log/slog", "Handler")
    or
    exists(PointerType p | p.getBaseType() = t and p.implements("log/slog", "Handler"))
  )
}

/**
 * Holds when every slog handler of the program is a standard library one.
 *
 * slog.JSONHandler and slog.TextHandler write each record on one line: they
 * escape or quote every control character of the message, of the attribute
 * keys and of the attribute values, so no value can end a record or forge
 * another. The same holds for the handler behind slog.Default. This is the
 * property CodeQL does not model. It stops holding, and the alerts come back,
 * as soon as the program declares its own slog.Handler or builds a logger from
 * a handler that is not directly a standard library one.
 */
predicate slogHandlersAreStandard() {
  not foreignHandlerLogger(_) and
  not customHandlerType(_)
}

/** An argument of a call to log/slog, the only package this query vouches for. */
class SlogMessageComponent extends DataFlow::Node {
  SlogMessageComponent() {
    exists(LoggerCall logger |
      this = logger.getAMessageComponent() and
      logger.(DataFlow::CallNode).getTarget().getPackage().getPath() = "log/slog"
    )
  }
}

module PreviewdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { LogInjection::Config::isSource(source) }

  predicate isSink(DataFlow::Node sink) { LogInjection::Config::isSink(sink) }

  predicate isBarrier(DataFlow::Node node) {
    LogInjection::Config::isBarrier(node)
    or
    slogHandlersAreStandard() and node instanceof SlogMessageComponent
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module PreviewdFlow = TaintTracking::Global<PreviewdConfig>;

import PreviewdFlow::PathGraph

from PreviewdFlow::PathNode source, PreviewdFlow::PathNode sink
where PreviewdFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
