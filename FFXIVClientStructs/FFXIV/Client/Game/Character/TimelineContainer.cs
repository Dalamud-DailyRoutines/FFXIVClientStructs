using FFXIVClientStructs.FFXIV.Client.Game.Control;
using FFXIVClientStructs.FFXIV.Client.Game.Object;

namespace FFXIVClientStructs.FFXIV.Client.Game.Character;

// Client::Game::Character::TimelineContainer
//   Client::Game::Character::ContainerInterface
[GenerateInterop]
[Inherits<ContainerInterface>]
[StructLayout(LayoutKind.Explicit, Size = 0x350)]
public unsafe partial struct TimelineContainer {
    [FieldOffset(0x10)] public ActionTimelineSequencer TimelineSequencer;
    [FieldOffset(0x200)] public TimelineTransitController TimelineTransit;
    [FieldOffset(0x2C0)] public byte ModelState;
    [FieldOffset(0x2C1), FixedSizeArray] internal FixedSizeArray2<byte> _animationState;

    [FieldOffset(0x2C8)] public float OverallSpeed; // The overall speed which is applied to all slots as well as things like particles attached to the owner

    [FieldOffset(0x2E6)] public ushort BaseOverride; // Forces base animation when character is in a Normal or AnimLock state
    [FieldOffset(0x2E8)] public ushort LipsOverride; // Forces the character lips to play timeline

    [FieldOffset(0x308)] public nint BannerTimelineSheet; // only set when loading data
    [FieldOffset(0x310)] public nint BannerTimelineRowDescriptor; // only set when loading data
    [FieldOffset(0x318)] public ushort BannerTimelineRowId;
    [FieldOffset(0x31A)] public byte BannerFacialRowId;

    // contained in a small 0x10 struct
    [FieldOffset(0x320 + 0x0)] public float BannerRequestStartTimestamp;

    [FieldOffset(0x330 + 0x00), CExporterExcelBegin("BannerTimeline")] public uint BannerTimelineNameOffset;
    [FieldOffset(0x330 + 0x04)] public uint BannerTimelineAdditionalData;
    [FieldOffset(0x330 + 0x08)] public int BannerTimelineIcon;
    [FieldOffset(0x330 + 0x0C)] public ushort BannerTimelineUnlockCondition;
    [FieldOffset(0x330 + 0x0E)] public ushort BannerTimelineUnknown_70_1;
    [FieldOffset(0x330 + 0x10)] public ushort BannerTimelineUnknown_70_2;
    [FieldOffset(0x330 + 0x12)] public ushort BannerTimelineUnknown0;
    [FieldOffset(0x330 + 0x14)] public ushort BannerTimelineSortKey;
    [FieldOffset(0x330 + 0x16)] public byte BannerTimelineType;
    [FieldOffset(0x330 + 0x17)] public byte BannerTimelineAcceptClassJobCategory;
    [FieldOffset(0x330 + 0x18), CExporterExcelEnd] public byte BannerTimelineCategory;

    [FieldOffset(0x348)] public byte Flags1;
    [FieldOffset(0x349)] public byte Flags2; // bit 2 makes it load the requested banner animation

    // 0x40 = WeaponDrawn
    [FieldOffset(0x34E)] public byte Flags3;

    /// <summary> Computes height difference between the player the action timeline belongs to and target to height adjust emotes. </summary>
    /// <param name="target"> The object id of the target of the emote. </param>
    /// <param name="emoteId"> The row id of the executed emote. </param>
    /// <returns> Returns 0 or one of the row ids for height adjustment for emotes (like kneeling to hug small objects). </returns>
    [MemberFunction("E8 ?? ?? ?? ?? 44 0F B7 E8 45 85 ED")]
    public partial uint GetHeightAdjustActionTimelineRowId(GameObjectId target, uint emoteId);

    // 7.0: inlined
    // [MemberFunction("E8 ?? ?? ?? ?? 48 8B 4B ?? F3 0F 10 B1")]
    // public partial void SetSlotSpeed(uint slot, float speed); // Sets the speed of the animation slot on the target actor and any children (mounts, ornaments)

    [MemberFunction("0F B7 C2 4C 8B C9 3D 72 02 00 00")]
    public partial void SetLipsOverrideTimeline(ushort actionTimelineId);

    [MemberFunction("40 53 48 83 EC 30 48 8B D9 0F 29 74 24 ?? 48 8B 49 08 E8 ?? ?? ?? ?? 0F 28 F0 0F 57 C9 0F 2F F1 0F 86 ?? ?? ?? ?? 48 8B 4B 08 48 8B 01 FF 50 10 83 F8 08 75 60 48 8B 4B 08 48 89 7C 24 ?? E8 ?? ?? ?? ?? 48 8B F8 48 85 C0 74 45 66 83 B8 ?? ?? ?? ?? ?? 74 3B 48 8D 88 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 2B 0F B7 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1A 0F B6 40 50 66 0F 6E C0 0F 5B C0 F3 0F 59 C6 0F 28 F0 F3 0F 5E 35 ?? ?? ?? ?? 48 8B 7C 24 ?? F6 83")]
    public partial bool CalculateAndApplyOverallSpeed(); // Calculates the current overall speed and applies it, returns true if the speed changed

    [MemberFunction("E8 ?? ?? ?? ?? EB 48 48 8B 45 08")]
    public partial void PlayActionTimeline(ushort introId, ushort loopId = 0, void* a4 = null);
}
