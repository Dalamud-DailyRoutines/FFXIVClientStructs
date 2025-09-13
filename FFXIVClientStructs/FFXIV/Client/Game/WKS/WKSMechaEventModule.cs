namespace FFXIVClientStructs.FFXIV.Client.Game.WKS;

// Client::Game::WKS::WKSMechaEventModule
//   Client::Game::WKS::WKSModuleBase
// MechaEvent
[GenerateInterop]
[Inherits<WKSModuleBase>]
[StructLayout(LayoutKind.Explicit, Size = 0xA2B0)]
public unsafe partial struct WKSMechaEventModule {
    [FieldOffset(0x30), FixedSizeArray] internal FixedSizeArray2<WKSMechaEvent> _events;
    [FieldOffset(0xA290)] public WKSMechaEvent* CurrentEvent;

    [FieldOffset(0xA2A4)] public WKSEventModuleFlag Flags;
}

[Flags]
public enum WKSEventModuleFlag : uint {
    HasCurrentEvent = 1 << 0, // the pointer. doesn't mean it's active
    PilotApplicationSubmitted = 1 << 1,
    PilotApplicationAccepted = 1 << 2,
    PilotCutscenePlaying = 1 << 3,
    IsJoined = 1 << 7,
}
