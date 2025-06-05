using FFXIVClientStructs.FFXIV.Client.System.String;

namespace FFXIVClientStructs.FFXIV.Client.Game.Object;

[GenerateInterop]
[Inherits<GameObject>]
[StructLayout(LayoutKind.Explicit, Size = 0x230)]
public unsafe partial struct MJIObject {
    [FieldOffset(0x1A8)] public Utf8String SgbPath;
    [FieldOffset(0x22C)] public uint EObjNameId;
}
