using System;
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

sealed class TraceEventSessionSource(TraceEventSession session, TraceEventDispatcher source, bool stacksEnabled) : IDisposable {
	static readonly TraceEventProviderOptions DefaultOptions = new();
	static readonly TraceEventProviderOptions StacksEnabledOptions = new() { StacksEnabled = true };

	bool isDisposed;

	public TraceEventSession Session { get; } = session;

	public TraceEventDispatcher Source { get; } = source;

	public bool StacksEnabled { get; } = stacksEnabled;

	public SymbolReader? SymbolReader { get; set; }

	public static TraceEventSessionSource Create(string sessionName, bool stacksEnabled = false) {
		var session = new TraceEventSession(sessionName);

		// For resolving process names and call stacks
		var flags = KernelTraceEventParser.Keywords.Process;
		if (stacksEnabled)
			flags |= KernelTraceEventParser.Keywords.ImageLoad;
		session.EnableKernelProvider(flags);

		return Create(session, stacksEnabled);
	}

	public static TraceEventSessionSource Create(TraceEventSession session, bool stacksEnabled = false) {
		return new TraceEventSessionSource(session, stacksEnabled ? TraceLog.CreateFromTraceEventSession(session, 50) : session.Source, stacksEnabled);
	}

	public void AddDynamicCallback(string providerName, Action<TraceEventSnapshot> callback) {
		AddDynamicCallback(providerName, true, null, null, null, callback);
	}

	public void AddDynamicCallback(string providerName, bool? stacksEnabled, Action<TraceEventSnapshot> callback) {
		AddDynamicCallback(providerName, true, stacksEnabled, null, null, callback);
	}

	public void AddDynamicCallback(string providerName, Predicate<string> preFilter, Action<TraceEventSnapshot> callback) {
		AddDynamicCallback(providerName, true, null, preFilter, null, callback);
	}

	public void AddDynamicCallback(string providerName, Predicate<TraceEvent> postFilter, Action<TraceEventSnapshot> callback) {
		AddDynamicCallback(providerName, true, null, null, postFilter, callback);
	}

	public void AddDynamicCallback(string providerName, Predicate<string> preFilter, Predicate<TraceEvent> postFilter, Action<TraceEventSnapshot> callback) {
		AddDynamicCallback(providerName, true, null, preFilter, postFilter, callback);
	}

	public void AddDynamicCallback(string providerName, bool enableProvider, bool? stacksEnabled, Predicate<string>? preFilter, Predicate<TraceEvent>? postFilter, Action<TraceEventSnapshot> callback) {
		if (string.IsNullOrEmpty(providerName))
			throw new ArgumentException("Provider name cannot be null or empty.", nameof(providerName));

		bool b = stacksEnabled ?? StacksEnabled;
		if (enableProvider)
			Session.EnableProvider(providerName, options: b ? StacksEnabledOptions : DefaultOptions);
		Source.Dynamic.AddCallbackForProviderEvents(EventFilter, Callback);

		EventFilterResponse EventFilter(string pName, string eName) {
			if (pName != providerName)
				return EventFilterResponse.RejectProvider;

			if (preFilter is null)
				return EventFilterResponse.AcceptEvent;

			if (preFilter(eName))
				return EventFilterResponse.AcceptEvent;

			return EventFilterResponse.RejectEvent;
		}

		void Callback(TraceEvent data) {
			if (postFilter is null || postFilter(data))
				callback(new TraceEventSnapshot(data));
		}
	}

	public void AddUnhandledCallback(Guid providerGuid, Action<TraceEventSnapshot> callback) {
		AddUnhandledCallback(providerGuid, null, callback);
	}

	public void AddUnhandledCallback(Guid providerGuid, bool? stacksEnabled, Action<TraceEventSnapshot> callback) {
		bool b = stacksEnabled ?? StacksEnabled;
		Session.EnableProvider(providerGuid, options: b ? StacksEnabledOptions : DefaultOptions);
		Source.UnhandledEvents += data => callback(new TraceEventSnapshot(data));
	}

	public void Dispose() {
		if (!isDisposed) {
			isDisposed = true;
			Source.Dispose();
			Session.Dispose();
		}
	}
}
