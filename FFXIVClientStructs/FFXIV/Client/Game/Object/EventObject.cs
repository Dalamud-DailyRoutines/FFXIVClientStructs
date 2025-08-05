namespace FFXIVClientStructs.FFXIV.Client.Game.Object;

// Client::Game::Object::EventObject
//   Client::Game::Object::GameObject
[GenerateInterop]
[Inherits<GameObject>]
[StructLayout(LayoutKind.Explicit, Size = 0x1C0)]
public unsafe partial struct EventObject {
    [FieldOffset(0x1A0), CExporterExcel("EObj")] public nint EObjRowPtr;
    [FieldOffset(0x1A8), CExporterExcel("ExportedSG")] public nint ExportedSGRowPtr;
}
