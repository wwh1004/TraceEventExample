using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

static class Program {
	static readonly DateTime StartTime = DateTime.Now;
	static readonly ILogger EventOnlyLogger = new LoggerConfiguration().WriteTo.File($"events_{StartTime:yyyyMMdd-HHmmss}.json", outputTemplate: "{Message:lj}{NewLine}{Exception}").MinimumLevel.Verbose().CreateLogger();
	static readonly ILogger StatisticsOnlyLogger = new LoggerConfiguration().WriteTo.File($"statistics_{StartTime:yyyyMMdd-HHmmss}.json", outputTemplate: "{Message:lj}{NewLine}{Exception}").MinimumLevel.Verbose().CreateLogger();

	static async Task Main(string[] args) {
		Log.Logger = new LoggerConfiguration()
			.WriteTo.Console(Debugger.IsAttached ? LogEventLevel.Verbose : LogEventLevel.Information, outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code)
			.WriteTo.File($"log_{StartTime:yyyyMMdd-HHmmss}.txt")
			.MinimumLevel.Verbose()
			.CreateLogger();

		using var source = CreateDefenderSource_Filtered();

		try {
			await ProcessSourceAsync(source, CancellationToken.None);
		}
		catch (OperationCanceledException) {
		}
	}

	static TraceEventSessionSource CreateDefenderSource_AllProviders() {
		Debug.Assert(TraceEventProviders.GetEventSourceGuidFromName("Microsoft.Windows.TlgAggregateInternal") == Guid.Parse("{703fcc13-b66f-5868-ddd9-e2db7f381ffb}"));

		var source = TraceEventSessionSource.Create("DefenderTrace", true);

		source.AddDynamicCallback("Microsoft-Antimalware-AMFilter", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-Engine", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-Protection", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-RTP", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-Scan-Interface", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-Service", LogEvent);
		source.AddDynamicCallback("Microsoft-Antimalware-UacScan", LogEvent);
		source.AddDynamicCallback("Microsoft-Windows-Windows Defender", LogEvent);

		// {7af898d7-7e0e-518d-5f96-b1e79239484c} TraceLogging
		source.AddDynamicCallback("Microsoft.Windows.Defender", LogEvent);

		// ProcessStart/ProcessStop
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Process", (string eventName) => eventName.Split('/')[0] is
			"ProcessStart" or
			"ProcessStop", LogEvent);

		// KERNEL_AUDIT_API_TERMINATEPROCESS
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Audit-API-Calls", (string eventName) => eventName is
			"EventID(2)", LogEvent);

		return source;
	}

	static TraceEventSessionSource CreateDefenderSource_Filtered() {
		Debug.Assert(TraceEventProviders.GetEventSourceGuidFromName("Microsoft.Windows.TlgAggregateInternal") == Guid.Parse("{703fcc13-b66f-5868-ddd9-e2db7f381ffb}"));

		var source = TraceEventSessionSource.Create("DefenderTrace", true);

		source.AddDynamicCallback("Microsoft-Antimalware-AMFilter", (string eventName) => eventName is
			not "AMFilter_CacheHit" and
			not "AMFilter_DeleteStreamContext" and
			not "AMFilter_FileScan", LogEvent);

		source.AddDynamicCallback("Microsoft-Antimalware-Engine", eventName => eventName is
			not "BehaviorMonitoring/BmNotificationHandleStart" and
			not "BehaviorMonitoring/BmOpenProcess" and
			not "BehaviorMonitoring/BmModuleLoad" and
			not "BehaviorMonitoring/BmEtw" and
			not "MetaStoreTask/MetaStoreAction" and
			not "Streamscanrequest/Start" and
			not "Streamscanrequest/Stop" and
			not "UfsScanFileTask/Start" and
			not "ExpensiveOperationTask/ExpensiveOperationBegin" and
			not "Cache/MOACLookup" and
			not "Cache/CacheLookup", data => {
				if (data.EventName == "BehaviorMonitoring/BmNotificationHandleStop")
					return data.PayloadByName("MatchedThreatsNumber") is int n && n != 0;
				return true;
			}, LogEvent);

		source.AddDynamicCallback("Microsoft-Antimalware-Protection", LogEvent);

		source.AddDynamicCallback("Microsoft-Antimalware-RTP", (string eventName) => eventName is
			not "RTPPriority", LogEvent);

		source.AddDynamicCallback("Microsoft-Antimalware-Scan-Interface", LogEvent);

		// Uselsess events
		//source.AddDynamicCallback("Microsoft-Antimalware-Service", LogEvent);

		source.AddDynamicCallback("Microsoft-Antimalware-UacScan", LogEvent);

		source.AddDynamicCallback("Microsoft-Windows-Windows Defender", (string eventName) => eventName is
			not "EventID(5007)", LogEvent);

		// {7af898d7-7e0e-518d-5f96-b1e79239484c} TraceLogging
		source.AddDynamicCallback("Microsoft.Windows.Defender", (string eventName) => eventName is
			not "Engine.GenericHResult" and
			not "Engine.GenericCount", LogEvent);

		// ProcessStart/ProcessStop
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Process", (string eventName) => eventName.Split('/')[0] is
			"ProcessStart" or
			"ProcessStop", LogEvent);

		// KERNEL_AUDIT_API_TERMINATEPROCESS
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Audit-API-Calls", (string eventName) => eventName is
			"EventID(2)", LogEvent);

		return source;
	}

	static TraceEventSessionSource CreateKernalAPISource() {
		var source = TraceEventSessionSource.Create("KernalAPITrace", true);

		// KERNEL_AUDIT_API_TERMINATEPROCESS
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Audit-API-Calls", (TraceEvent data) => data.ID == (TraceEventID)2, LogEvent);

		return source;
	}

	static TraceEventSessionSource CreateThreatIntelligenceSource() {
		var source = TraceEventSessionSource.Create("TiTrace");

		source.AddDynamicCallback("Microsoft-Windows-Threat-Intelligence", LogEvent);

		return source;
	}

	static TraceEventSessionSource CreateProcessTraceSource_Raw() {
		var session = new TraceEventSession("ProcessTrace");

		// For resolving process names and call stacks
		var flags = KernelTraceEventParser.Keywords.Process;
		session.EnableKernelProvider(flags);

		// TODO: 似乎是有BUG，MSNT_SystemTrace的Version为高版本的时候，payloadNames没有包含高版本的字段。只能用Kernel.ProcessStart解析才是正确的。
		session.Source.Dynamic.All += data => {
			LogEvent(new TraceEventSnapshot(data));
		};

		return new TraceEventSessionSource(session, session.Source, false);
	}

	static TraceEventSessionSource CreateProcessTraceSource() {
		var source = TraceEventSessionSource.Create("ProcessTrace", false);

		source.Session.Source.Dynamic.All += _ => { };
		source.Session.Source.Kernel.ProcessStart += data => {
			LogEvent(new TraceEventSnapshot(data));
		};
		// ProcessStart/ProcessStop
		source.AddDynamicCallback("Microsoft-Windows-Kernel-Process", (TraceEvent data) => (ushort)data.ID is 1 or 2, data => {
			LogEvent(data);
		});

		source.AddDynamicCallback("MSNT_SystemTrace", false, false, eventName => eventName == "Process/Start", null, data => {
			LogEvent(data);
		});
		//source.Source.Dynamic.All += data => {
		//	LogEvent(new TraceEventSnapshot(data));
		//};

		return source;
	}

	static TraceEventSessionSource CreatePowerShellTraceSource() {
		var source = TraceEventSessionSource.Create("PowerShellTrace", true);

		source.AddDynamicCallback("Microsoft-Windows-PowerShell", LogEvent);

		return source;
	}

	static TraceEventSessionSource CreateCOMTraceSource() {
		var source = TraceEventSessionSource.Create("COMTrace", true);

		source.AddDynamicCallback("Microsoft-Windows-Services", LogEvent);

		source.AddDynamicCallback("Microsoft-Windows-COMRuntime", (TraceEvent data) => data.ID != (TraceEventID)32769, LogEvent);

		//// WPP_ThisDir_CTLGUID_OLE32
		//var ignoredClsids = File.ReadAllLines("IgnoredClsids.txt");
		//source.AddUnhandledCallback(Guid.Parse("{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}"), false, data => {
		//	var sb = new StringBuilder();
		//	foreach (byte b in data.EventData) {
		//		if (!char.IsControl((char)b))
		//			sb.Append((char)b);
		//	}
		//	var s = sb.ToString();

		//	bool log;
		//	if (s.Contains("services.cxx"))
		//		log = true;
		//	else if (s.Contains("CComActivator::DoCreateInstance"))
		//		log = s.Contains("End CCI clsid:") && ignoredClsids.All(x => !s.Contains(x));
		//	else
		//		log = false;

		//	if (log) {
		//		Log.Information("Unhandled:" + Environment.NewLine +
		//			"{StringDump}" + Environment.NewLine +
		//			"{HexDump}", s, DumpByteArray(data.EventData));
		//		GC.Collect();
		//	}
		//});

		return source;
	}

	static string DumpByteArray(byte[] data, int lc = 16) {
		var sb = new StringBuilder();
		for (int i = 0; i < data.Length; i++) {
			if (i % lc == 0) {
				if (i != 0)
					sb.Append(Environment.NewLine);
				sb.Append($"{i:X4}  ");
			}
			sb.Append($"{data[i]:X2} ");
			if (i % lc == lc - 1 || i == data.Length - 1) {
				int missing = lc - (i % lc) - 1;
				sb.Append(' ', (missing * 3) + 2);
				sb.Append(' ');
				for (int j = i - (i % lc); j <= i; j++) {
					sb.Append(char.IsControl((char)data[j]) ? '.' : (char)data[j]);
				}
			}
		}
		return sb.ToString();
	}

	static readonly Dictionary<string, HashSet<string>> FilteredEvents = new() {
		["Microsoft.Windows.Defender"] = [
			"Platform.Maps.SOAPFeature",
			"Platform.Maps.Latency",
			"Platform.Maps.SendReportComplete",
			"Platform.Maps.ThreadCount",
			"Platform.Maps.SendReportStart",
			"Platform.Configuration.ConfigurationChanged"
		]
	};

	static readonly Dictionary<string, HashSet<string>> FilteredPayloads = new() {
		["Microsoft.Windows.Defender"] = [
			"PartA_PrivTags",
			"ProductGuid",
			"EngineVersion",
			"SigVersion",
			"AppVersion",
			"PartnerGuid",
			"OrgId",
			"IsBeta",
			"IsManaged",
			"IsPassiveMode",
			"IsSxsPassiveMode",
			"ShouldHashIds",
			"EngineRing",
			"CampRing",
			"SignatureRing"
		]
	};

	static readonly Dictionary<string, Dictionary<string, int>> EventCounts = [];

	static string[] SkipStackFrames(string[] callStack) {
		bool isKernel = callStack.Length != 0 && callStack[0].Contains("ntoskrnl!");
		int indexA = 0;
		if (isKernel) {
			bool omitted = false;
			for (; indexA < callStack.Length; indexA++) {
				if (callStack[indexA].Contains("ntoskrnl!EtwWriteTransfer")) {
					omitted = true;
					break;
				}
			}
			if (!omitted)
				return callStack;
			indexA++;
		}
		else {
			if (!(callStack.Length > 2 &&
				callStack[0].Contains("ntdll!NtTraceEvent") &&
				callStack[1].Contains("ntdll!EtwEventWriteTransfer")))
				return callStack;
			indexA = 2;
		}

		bool isTraceLogging = false;
		bool isManifest = false;
		int indexB = indexA;
		for (; indexB < callStack.Length; indexB++) {
			bool omitted = false;
			string temp;
			switch (indexB - indexA) {
			case 0:
				omitted = isTraceLogging = callStack[indexB].Contains("!_tlgWriteTransfer_");
				if (!isTraceLogging)
					omitted = isManifest = callStack[indexB].Contains("!McGenEventWrite_");
				break;
			case 1:
				if (isTraceLogging)
					temp = "!tlgWriteTemplate";
				else if (isManifest)
					temp = isKernel ? "!McTemplateK0" : "!McTemplateU0";
				else
					break;
				omitted = callStack[indexB].Contains(temp);
				break;
			}
			if (!omitted)
				break;
		}

		if (indexB != 0)
			callStack = callStack.Skip(indexB).ToArray();
		return callStack;
	}

	[MethodImpl(MethodImplOptions.Synchronized)]
	static void LogEvent(TraceEventSnapshot data) {
		if (FilteredEvents.TryGetValue(data.ProviderName, out var f1) && f1.Contains(data.EventName))
			return;
		if (!EventCounts.TryGetValue(data.ProviderName, out var counts))
			EventCounts[data.ProviderName] = counts = [];
		if (counts.TryGetValue(data.EventName, out int count))
			counts[data.EventName] = count + 1;
		else
			counts[data.EventName] = 1;
		Dictionary<string, object> payloads;
		if (FilteredPayloads.TryGetValue(data.ProviderName, out var f2)) {
			payloads = data.Payloads.Where(t => !f2.Contains(t.Key)).ToDictionary(t => t.Key, t => t.Value);
		}
		else {
			payloads = data.Payloads.ToDictionary(t => t.Key, t => t.Value);
		}
		var callStack = SkipStackFrames(data.CallStack);
		var obj = new {
			data.EventIndex,
			data.TimeStamp,
			data.Level,
			data.ProviderName,
			data.EventName,
			data.ProcessID,
			data.ProcessName,
			Payloads = payloads,
			CallStack = callStack
		};
		EventOnlyLogger.Information("{@Event}", obj);
		Log.Information("[{Level}] [{ProviderName}/{EventName}] Process: {ProcessID} ({ProcessName}) Payloads: {@Payloads}", data.Level, data.ProviderName, data.EventName, data.ProcessID, data.ProcessName, payloads);
	}

	static async Task ProcessSourceAsync(TraceEventSessionSource source, CancellationToken cancellationToken) {
		if (cancellationToken.IsCancellationRequested)
			return;

		int eventsLost = 0;
		using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		cancellationToken = cts.Token;
		using var ctr = cancellationToken.Register(() => {
			eventsLost = source.Session.EventsLost;
			source.Session.Stop(true);
		});

		try {
			Console.CancelKeyPress += CancelHandler;

			var processTask = Task.Run(() => {
				try {
					source.Source.Process();
					cancellationToken.ThrowIfCancellationRequested();
				}
				catch (OperationCanceledException) {
					Log.Warning("Operation canceled, exiting process loop");
					throw;
				}
				catch (Exception ex) {
					Log.Error(ex, "Exception occurred while processing events");
				}
				finally {
					var counts = EventCounts.Select(t => new { ProviderName = t.Key, Events = t.Value.OrderByDescending(t => t.Value).ToDictionary(t => t.Key, t => t.Value) }).ToArray();
					var statistics = new {
						StartTime,
						EventsLost = eventsLost,
						Counts = counts
					};
					StatisticsOnlyLogger.Information("{@Statistics}", statistics);
				}
				Debug.Assert(false);
				Log.Error("Unexpected exit from process loop");
			}, cancellationToken);

			var flushEventTask = Task.Run(async () => {
				try {
					while (true) {
						source.Session.Flush();
						await Task.Delay(10, cancellationToken);
					}
				}
				catch (OperationCanceledException) {
					Log.Warning("Operation canceled, exiting flush event loop");
					throw;
				}
				catch (Exception ex) {
					Log.Error(ex, "Exception occurred while flushing events");
				}
				Debug.Assert(false);
				Log.Error("Unexpected exit from flush event loop");
			}, cancellationToken);

			await Task.WhenAll(processTask, flushEventTask);
		}
		finally {
			// Spawn a new task to avoid deadlock (SetConsoleCtrlHandler will block until the running handler returns)
			ThreadPool.QueueUserWorkItem(_ => Console.CancelKeyPress -= CancelHandler);
		}

		void CancelHandler(object? sender, ConsoleCancelEventArgs args) {
			Log.Information("Cancellation requested, stopping session");
			cts.Cancel();
			args.Cancel = true;
		}
	}
}

static class StackTraceService {
	public static string[] PrintCallStack(TraceCallStack callStack) {
		var frames = new List<string>();
		var current = callStack;
		while (current != null) {
			// Asynchronously resolve symbols for the module if they've not been resolved before.
			// You can do this synchronously by just removing the call to ResolveSymbolsForModule from the Task and calling synchronously.
			if (string.IsNullOrEmpty(current.CodeAddress.FullMethodName) && !ResolvedSymbolsForModule(current.CodeAddress.ModuleFile)) {
				var t = current;
				ResolveSymbolsForModule(t.CodeAddress.CodeAddresses, t.CodeAddress.ModuleFile);
			}

			var frame = $"[0x{current.CodeAddress.Address:X}] {current.CodeAddress.ModuleName}!{current.CodeAddress.FullMethodName}";
			if (current.CodeAddress.Method is TraceMethod method) {

				if (method.MethodModuleFile is TraceModuleFile module) {
					uint rva = (uint)(current.CodeAddress.Address - module.ImageBase);
					uint offset = rva - (uint)method.MethodRva;
					frame += $"+0x{offset:X}";
				}
				else {
					Debug.Assert(false, "Method should have a module.");
					frame += "+0x??";
				}
			}
			//Console.WriteLine(frame);
			frames.Add(frame);
			current = current.Caller;
		}
		return [.. frames];
	}

	private static readonly HashSet<string> ResolvedModules = new();
	private static readonly SymbolReader SymbolReader = new(StreamWriter.Null, "SRV*C:\\Symbols\\") {
		Options = SymbolReaderOptions.CacheOnly | SymbolReaderOptions.NoNGenSymbolCreation,
		SecurityCheck = _ => true,
	};
	private static readonly FieldInfo PdbName = typeof(TraceModuleFile).GetField("pdbName", BindingFlags.NonPublic | BindingFlags.Instance) ?? throw new InvalidOperationException("pdbName field not found.");
	private static readonly FieldInfo PdbSignature = typeof(TraceModuleFile).GetField("pdbSignature", BindingFlags.NonPublic | BindingFlags.Instance) ?? throw new InvalidOperationException("pdbSignature field not found.");
	private static readonly FieldInfo PdbAge = typeof(TraceModuleFile).GetField("pdbAge", BindingFlags.NonPublic | BindingFlags.Instance) ?? throw new InvalidOperationException("pdbAge field not found.");

	private static bool ResolvedSymbolsForModule(TraceModuleFile moduleFile) {
		if (moduleFile == null) {
			// Treat null modules as already resolved, since there's nothing that we can do to resolve them.
			return true;
		}

		if (moduleFile.PdbSignature == Guid.Empty) {
			var dllFilePath = BypassSystem32FileRedirection(moduleFile.FilePath);
			if (File.Exists(dllFilePath)) {
				using var peFile = new PEFile.PEFile(dllFilePath);
				if (peFile.GetPdbSignature(out var pdbName, out var pdbGuid, out var pdbAge, true)) {
					PdbName.SetValue(moduleFile, pdbName);
					PdbSignature.SetValue(moduleFile, pdbGuid);
					PdbAge.SetValue(moduleFile, pdbAge);
				}
			}
		}

		bool resolvedSymbols = true;
		if (!ResolvedModules.Contains(moduleFile.PdbLookupValue())) {
			lock (ResolvedModules) {
				if (!ResolvedModules.Contains(moduleFile.PdbLookupValue())) {
					resolvedSymbols = false;
				}
			}
		}

		return resolvedSymbols;


		static string BypassSystem32FileRedirection(string path) {
			if (0 <= path.IndexOf("System32\\", StringComparison.OrdinalIgnoreCase)) {
				var winDir = Environment.GetEnvironmentVariable("WinDir");
				if (winDir != null) {
					var system32 = Path.Combine(winDir, "System32");
					if (path.StartsWith(system32, StringComparison.OrdinalIgnoreCase)) {
						if (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432") != null) {
							var sysNative = Path.Combine(winDir, "Sysnative");
							var newPath = Path.Combine(sysNative, path.Substring(system32.Length + 1));
							if (File.Exists(newPath)) {
								path = newPath;
							}
						}
					}
				}
			}
			return path;
		}
	}

	private static void ResolveSymbolsForModule(TraceCodeAddresses codeAddresses, TraceModuleFile moduleFile) {
		// Treat null modules as already resolved, since there's nothing that we can do to resolve them.
		if (moduleFile == null) {
			return;
		}

		codeAddresses.LookupSymbolsForModule(SymbolReader, moduleFile);
	}
}

internal static class TraceModuleFileExtensions {
	internal static string PdbLookupValue(this TraceModuleFile moduleFile) {
		return moduleFile.Name + moduleFile.PdbAge + moduleFile.PdbSignature;
	}
}
