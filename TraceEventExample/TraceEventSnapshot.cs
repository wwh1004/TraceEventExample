using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;

record TraceEventSnapshot(string ProviderName, string EventName, TraceEventID ID, TraceEventTask Task, string TaskName, TraceEventOpcode Opcode,
	string OpcodeName, TraceEventLevel Level, TraceEventKeyword Keywords, DateTime TimeStamp, double TimeStampRelativeMSec, int ThreadID,
	int ProcessID, string ProcessName, int ProcessorNumber, int PointerSize, EventIndex EventIndex, bool IsClassicProvider, bool IsTraceMessage,
	bool IsUnhandled, byte[] EventData, IReadOnlyDictionary<string, object> Payloads, string[] CallStack) {

	public TraceEventSnapshot(TraceEvent data)
		: this(data.ProviderName, data.EventName, data.ID, data.Task, data.TaskName, data.Opcode, data.OpcodeName, data.Level, data.Keywords,
			  data.TimeStamp, data.TimeStampRelativeMSec, data.ThreadID, data.ProcessID, data.ProcessName, data.ProcessorNumber, data.PointerSize,
			  data.EventIndex, data.IsClassicProvider, data.IsTraceMessage, data is UnhandledTraceEvent, GetEventData(data), GetPayloads(data),
			  GetCallStack(data)) {
	}

	static byte[] GetEventData(TraceEvent data) {
		if (data is UnhandledTraceEvent)
			return data.EventData();
		return [];
	}

#if NET8_0_OR_GREATER
	static FrozenDictionary<string, object> GetPayloads(TraceEvent data) {
		if (data is UnhandledTraceEvent)
			return FrozenDictionary<string, object>.Empty;
		return data.PayloadNames.Distinct().ToFrozenDictionary(t => t, t => data.PayloadByName(t));
	}
#else
	static IReadOnlyDictionary<string, object> GetPayloads(TraceEvent data) {
		if (data is UnhandledTraceEvent)
			return ImmutableDictionary<string, object>.Empty;
		return data.PayloadNames.Distinct().ToDictionary(t => t, t => data.PayloadByName(t));
		}
#endif

	static string[] GetCallStack(TraceEvent data) {
		if (data.Source is TraceLog)
			return StackTraceService.PrintCallStack(data.CallStack());
		return [];
	}
}
