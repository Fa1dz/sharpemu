// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Text;
using Microsoft.Extensions.Logging;
using SharpEmu.Core.Cpu.Debugging;
using SharpEmu.Core.Cpu.Native;
using SharpEmu.Core.Loader;
using SharpEmu.Core.Memory;
using SharpEmu.HLE;

namespace SharpEmu.Core.Cpu;

public sealed class CpuDispatcher : ICpuDispatcher, IDisposable
{
    private enum EntryFrameKind
    {
        ProcessEntry,
        ModuleInitializer,
    }

    private static class CpuLayout
    {
        public static ulong StackBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFF_F000_0000UL : 0x6FFF_F000_0000UL;
        public const ulong StackSize = 0x0020_0000UL;
        public static ulong TlsBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFE_0000_0000UL : 0x6FFE_0000_0000UL;
        public const ulong TlsSize = 0x0001_0000UL;
        public const ulong TlsPrefixSize = GuestTlsTemplate.StartupStaticTlsReservation;
        public static ulong BootstrapStubBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFD_F000_0000UL : 0x6FFD_F000_0000UL;
        public static ulong BootstrapPayloadBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFD_E000_0000UL : 0x6FFD_E000_0000UL;
        public static ulong DynlibFallbackStubBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFD_D000_0000UL : 0x6FFD_D000_0000UL;
        public static ulong ReturnToHostStubBaseAddress { get; } = OperatingSystem.IsWindows() ? 0x7FFD_C000_0000UL : 0x6FFD_C000_0000UL;
        public const ulong BootstrapRegionSize = 0x0000_1000UL;
        public const ulong ReturnToHostStubStride = 0x0100_0000UL;
        public const ulong BootstrapPayloadResultOffset = 0x28UL;
        public const ulong BootstrapStatusOffset = 0x100UL;
        public const ulong InitialRflags = 0x202;
        public const int MaxRetryAttempts = 32;
    }

    private static readonly byte[] BootstrapStubBytes = CreateStub(0xCC, 0xC3);
    private static readonly byte[] DynlibFallbackStubBytes = CreateStub(0x31, 0xC0, 0xC3);
    private static readonly byte[] ReturnToHostStubBytes = CreateStub(0xF4, 0xCC);

    private static byte[] CreateStub(params byte[] bytes)
    {
        var arr = new byte[CpuLayout.BootstrapRegionSize];
        Array.Copy(bytes, 0, arr, 0, bytes.Length);
        return arr;
    }

    private static readonly byte[] BootstrapStartSignature = new byte[]
    {
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
        0x41, 0x55, 0x41, 0x54, 0x53, 0x50, 0x48, 0x89,
    };

    private readonly IVirtualMemory _virtualMemory;
    private readonly IModuleManager _moduleManager;
    private readonly INativeCpuBackend _nativeCpuBackend;
    private readonly ILogger<CpuDispatcher> _logger;
    private bool _disposed;

    public CpuDispatcher(
        IVirtualMemory virtualMemory,
        IModuleManager moduleManager,
        INativeCpuBackend nativeCpuBackend,
        ILogger<CpuDispatcher> logger)
    {
        _virtualMemory = virtualMemory ?? throw new ArgumentNullException(nameof(virtualMemory));
        _moduleManager = moduleManager ?? throw new ArgumentNullException(nameof(moduleManager));
        _nativeCpuBackend = nativeCpuBackend ?? throw new ArgumentNullException(nameof(nativeCpuBackend));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public CpuExecutionResult DispatchEntry(
        ulong entryPoint,
        Generation generation,
        IReadOnlyDictionary<ulong, string>? importStubs = null,
        IReadOnlyDictionary<string, ulong>? runtimeSymbols = null,
        string processImageName = "eboot.bin",
        CpuExecutionOptions executionOptions = default)
    {
        _logger.LogInformation("DispatchEntry START: entryPoint=0x{EntryPoint:X16}, generation={Generation}", entryPoint, generation);
        return DispatchEntryCore(entryPoint, generation, importStubs, runtimeSymbols, processImageName, executionOptions, EntryFrameKind.ProcessEntry);
    }

    public CpuExecutionResult DispatchModuleInitializer(
        ulong entryPoint,
        Generation generation,
        IReadOnlyDictionary<ulong, string>? importStubs = null,
        IReadOnlyDictionary<string, ulong>? runtimeSymbols = null,
        string moduleName = "module",
        CpuExecutionOptions executionOptions = default)
    {
        _logger.LogInformation("DispatchModuleInitializer START: entryPoint=0x{EntryPoint:X16}, generation={Generation}, module={ModuleName}",
            entryPoint, generation, moduleName);
        return DispatchEntryCore(entryPoint, generation, importStubs, runtimeSymbols, moduleName, executionOptions, EntryFrameKind.ModuleInitializer);
    }

    private CpuExecutionResult DispatchEntryCore(
        ulong entryPoint,
        Generation generation,
        IReadOnlyDictionary<ulong, string>? importStubs,
        IReadOnlyDictionary<string, ulong>? runtimeSymbols,
        string imageName,
        CpuExecutionOptions executionOptions,
        EntryFrameKind frameKind)
    {
        if (!TryMapStackRegion(out var stackBase))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to map stack");
        if (!TryMapTlsRegion(out var tlsBase))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to map TLS");
        if (!TryMapReturnToHostStubRegion(out var returnStub))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to map return-to-host stub");

        var trackedMemory = new TrackedCpuMemory(_virtualMemory);
        var context = new CpuContext(trackedMemory, generation)
        {
            Rip = entryPoint,
            Rflags = CpuLayout.InitialRflags,
            FsBase = tlsBase,
            GsBase = tlsBase,
        };

        context[CpuRegister.Rsp] = stackBase + CpuLayout.StackSize - sizeof(ulong);
        if (!context.TryWriteUInt64(context[CpuRegister.Rsp], returnStub))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to push return stub");

        if (!InitializeGuestFrameChainSentinel(context))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to initialise frame chain");
        if (!InitializeTls(context, tlsBase))
            return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to initialise TLS");

        var effectiveImportStubs = importStubs is null
            ? new Dictionary<ulong, string>()
            : new Dictionary<ulong, string>(importStubs);

        bool entryParamsConfigured;
        if (frameKind == EntryFrameKind.ProcessEntry)
        {
            if (!TryMapDynlibFallbackStubRegion(out var exitHandler))
                return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to map exit handler stub");
            if (!InitializeProcessEntryFrame(context, imageName, exitHandler))
                return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to set up process entry frame");
            entryParamsConfigured = true;

            if (ShouldInjectBootstrapPayload(entryPoint))
            {
                if (!TryInstallBootstrapPayload(context, effectiveImportStubs))
                    return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to install bootstrap payload");
            }
        }
        else
        {
            if (!InitializeModuleInitializerFrame(context))
                return CpuExecutionResult.FromError(OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT, CpuExitReason.UnhandledException, entryPoint, "Failed to set up module initializer frame");
            entryParamsConfigured = false;
        }

        var milestoneLog = BuildEntryFrameDiagnostic(
            entryPoint,
            context,
            sentinelEnabled: true,
            sentinelValue: returnStub,
            entryParamsConfigured: entryParamsConfigured);

        if (executionOptions.CpuEngine != CpuExecutionEngine.NativeOnly)
        {
            var notImpl = new CpuNotImplementedInfo(
                CpuNotImplementedSource.NativeBackend,
                entryPoint,
                null,
                "cpu_engine_unsupported",
                executionOptions.CpuEngine.ToString(),
                "Unsupported CPU engine mode.");
            _logger.LogWarning("Unsupported CPU engine: {Engine}", executionOptions.CpuEngine);
            return new CpuExecutionResult(
                OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED,
                CpuExitReason.NativeBackendUnavailable,
                null,
                entryPoint,
                0, 0, 0, 0,
                notImplementedInfo: notImpl,
                milestoneLog: milestoneLog);
        }

        var debugHook = executionOptions.DebugHook;
        var debugFrame = debugHook is null
            ? null
            : new CpuContextDebugFrame(
                frameKind == EntryFrameKind.ProcessEntry
                    ? CpuDebugFrameKind.ProcessEntry
                    : CpuDebugFrameKind.ModuleInitializer,
                entryPoint,
                imageName,
                context,
                effectiveImportStubs);
        debugHook?.OnFrameEnter(debugFrame!);
        (_nativeCpuBackend as DirectExecutionBackend)?.SetActiveDebugFrame(debugFrame);

        var backendResult = _nativeCpuBackend.TryExecute(
            context,
            entryPoint,
            generation,
            effectiveImportStubs,
            runtimeSymbols ?? new Dictionary<string, ulong>(StringComparer.Ordinal),
            executionOptions,
            out var nativeResult);

        debugHook?.OnFrameExit(debugFrame!, nativeResult);

        var exitReason = backendResult
            ? (nativeResult == OrbisGen2Result.ORBIS_GEN2_OK ? CpuExitReason.ReturnedToHost : CpuExitReason.UnhandledException)
            : CpuExitReason.NativeBackendUnavailable;

        if (!backendResult)
        {
            var backendName = string.IsNullOrWhiteSpace(_nativeCpuBackend.BackendName)
                ? "native-backend" : _nativeCpuBackend.BackendName;
            var backendError = string.IsNullOrWhiteSpace(_nativeCpuBackend.LastError)
                ? "unknown backend error" : _nativeCpuBackend.LastError;
            var notImpl = new CpuNotImplementedInfo(
                CpuNotImplementedSource.NativeBackend,
                entryPoint,
                null,
                "cpu_engine_native_only",
                backendName,
                backendError);
            _logger.LogError("Native backend failed: {Error}", backendError);
            return new CpuExecutionResult(
                OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_IMPLEMENTED,
                CpuExitReason.NativeBackendUnavailable,
                null,
                context.Rip,
                0, 0, 0, 0,
                notImplementedInfo: notImpl,
                milestoneLog: milestoneLog + $"\nNative backend failed: {backendError}");
        }

        return new CpuExecutionResult(
            nativeResult,
            exitReason,
            null,
            context.Rip,
            0, 0, 0, 0,
            milestoneLog: milestoneLog);
    }

    private bool TryMapStackRegion(out ulong baseAddress) { /* ... */ }
    private bool TryMapTlsRegion(out ulong baseAddress) { /* ... */ }
    // ... (all other helpers as in the full version earlier)
    // I'm not repeating all 150 lines here to keep the answer readable.
    // The full version I gave in my previous message contains all of them.

    public void Dispose()
    {
        if (_disposed) return;
        (_nativeCpuBackend as IDisposable)?.Dispose();
        _disposed = true;
    }
}
