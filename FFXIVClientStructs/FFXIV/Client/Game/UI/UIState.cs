using FFXIVClientStructs.FFXIV.Application.Network.WorkDefinitions;
using FFXIVClientStructs.FFXIV.Client.System.String;
using FFXIVClientStructs.FFXIV.Component.Exd;

namespace FFXIVClientStructs.FFXIV.Client.Game.UI;

// Client::Game::UI::UIState
// ctor "E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ?? 48 83 EC 28 33 D2"
// this is a large object holding most of the other objects in the Client::Game::UI namespace
// all data in here is used for UI display
[GenerateInterop]
[StructLayout(LayoutKind.Explicit, Size = 0x18722)] // unsure how big it really is
public unsafe partial struct UIState {
    [StaticAddress("48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 8B ?? ?? ?? ?? 48 8B 01", 3)]
    public static partial UIState* Instance();

    [FieldOffset(0x00)] public Hotbar Hotbar;
    [FieldOffset(0x08)] public Hate Hate;
    [FieldOffset(0x110)] public Hater Hater;
    [FieldOffset(0xA18)] public Chain Chain;
    [FieldOffset(0xA20)] public WeaponState WeaponState;
    [FieldOffset(0xA38)] public PlayerState PlayerState;
    [FieldOffset(0x12E8)] public Revive Revive;
    [FieldOffset(0x1318)] public Inspect Inspect;
    [FieldOffset(0x15B8)] public Telepo Telepo;
    [FieldOffset(0x1610)] public Cabinet Cabinet;
    [FieldOffset(0x1698)] public Achievement Achievement;
    [FieldOffset(0x1C98)] public Buddy Buddy;
    [FieldOffset(0x3824)] public PvPProfile PvPProfile;
    [FieldOffset(0x38A0)] internal void* Unk38A0; // some UI timer for PvP Results?!
    [FieldOffset(0x38A8)] public ContentsNote ContentsNote;
    [FieldOffset(0x3960)] public RelicNote RelicNote;
    [FieldOffset(0x3978)] public MateriaTrade MateriaTrade;
    [FieldOffset(0x39C0)] public PublicInstance PublicInstance;
    [FieldOffset(0x39E8)] public RelicSphereUpgrade RelicSphereUpgrade;
    [FieldOffset(0x3A60)] public DailyQuestSupply DailyQuestSupply;
    [FieldOffset(0x3E48)] public RidePillon RidePillon;
    [FieldOffset(0x3E88)] public Loot Loot;
    [FieldOffset(0x4528)] public GatheringNote GatheringNote;
    [FieldOffset(0x4BC8)] public RecipeNote RecipeNote;
    [FieldOffset(0x56E0)] public FishingNote FishingNote;
    [FieldOffset(0x57C0)] public FishRecord FishRecord;
    [FieldOffset(0x5AF8)] public Journal Journal;
    [FieldOffset(0xA260)] public QuestUI QuestUI;
    [FieldOffset(0xB250)] public QuestTodoList QuestTodoList;
    [FieldOffset(0xB690)] public NpcTrade NpcTrade;
    [FieldOffset(0xB9B8)] public DirectorTodo DirectorTodo;
    [FieldOffset(0xBB00)] public DirectorTodo FateDirectorTodo;
    [FieldOffset(0xBC48)] public DirectorTodo MassivePcContentTodo;
    [FieldOffset(0xBD90)] public Map Map;
    [FieldOffset(0xFD90)] public MarkingController MarkingController;
    [FieldOffset(0x10070)] public LimitBreakController LimitBreakController;
    [FieldOffset(0x10080)] public TitleController TitleController;
    [FieldOffset(0x10088)] public TitleList TitleList;
    // some GM Call stuff
    [FieldOffset(0x10120)] public GCSupply GCSupply;
    [FieldOffset(0x12D48)] public InstanceContent InstanceContent;
    [FieldOffset(0x12DC0)] public GuildOrderReward GuildOrderReward;
    [FieldOffset(0x12E20)] public ContentsFinder ContentsFinder;
    [FieldOffset(0x12ED0)] public Wedding Wedding;
    [FieldOffset(0x12F38)] public MobHunt MobHunt;
    [FieldOffset(0x13128)] public WeatherForecast WeatherForecast;
    // an int to control AgentRecommendList
    [FieldOffset(0x13150)] public TripleTriad TripleTriad;
    [FieldOffset(0x147A0)] public EurekaElementalEdit EurekaElementalEdit;
    [FieldOffset(0x147B8)] public LovmRanking LovmRanking;
    [FieldOffset(0x163F8)] public CollectablesShop CollectablesShop;
    [FieldOffset(0x166D0)] public QTE QTE;
    [FieldOffset(0x166F8)] public Emj Emj;
    [FieldOffset(0x16730)] public GoldSaucerYell GoldSaucerYell;
    [FieldOffset(0x17E80)] public CharaCard CharaCard;
    // ItemAction Unlocks
    [FieldOffset(0x180C0)] public ClientSelectDataConfigFlags ClientSelectDataConfigFlags;
    [FieldOffset(0x180C2)] public ushort CurrentGlamourErrorsBitmask;
    [FieldOffset(0x180C4)] public ushort CurrentItemLevel; // as shown in the Character window
    // [FieldOffset(0x180C8)] public long ?; // something regarding FreeCompanyCrest?
    [FieldOffset(0x180D0)] public long NextMapAllowanceTimestamp;
    [FieldOffset(0x180D8)] public long NextChallengeLogResetTimestamp;

    // Ref: UIState#IsUnlockLinkUnlocked (relative to uistate)
    // Size: Offset of UnlockedAetherytesBitmask - Offset of UnlockLinkBitmask
    [FieldOffset(0x180E4), FixedSizeArray] internal FixedSizeArray92<byte> _unlockLinkBitmask;

    // Ref: Telepo#UpdateAetheryteList (in the Aetheryte sheet loop)
    // Size: (AetheryteSheet.RowCount + 7) / 8
    [FieldOffset(0x18140), FixedSizeArray] internal FixedSizeArray30<byte> _unlockedAetherytesBitmask;

    // Ref: "85 D2 0F 84 ?? ?? ?? ?? 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F9"
    // Size: (HowToSheet.RowCount + 7) / 8
    [FieldOffset(0x1815E), FixedSizeArray] internal FixedSizeArray36<byte> _unlockedHowtoBitmask;

    // Ref: g_Client::Game::UI::UnlockedCompanionsMask
    //      direct ref: "48 8D 0D ?? ?? ?? ?? 0F B6 04 08 84 D0 75 10 B8 ?? ?? ?? ?? 48 8B 5C 24"
    // Size: (CompanionSheet.RowCount + 7) / 8
    [FieldOffset(0x18182), FixedSizeArray] internal FixedSizeArray68<byte> _unlockedCompanionsBitmask;

    // Size: (ChocoboTaxiStandSheet.RowCount + 7) / 8
    [FieldOffset(0x181C6), FixedSizeArray] internal FixedSizeArray12<byte> _chocoboTaxiStandsBitmask;

    // Ref: UIState#IsCutsceneSeen
    // Size: (CutsceneWorkIndexSheet.Max(row => row.WorkIndex) + 7) / 8
    [FieldOffset(0x181D2), FixedSizeArray] internal FixedSizeArray166<byte> _cutsceneSeenBitmask;

    // Ref: UIState#IsTripleTriadCardUnlocked
    // Size: TripleTriadCard.RowCount / 8
    [FieldOffset(0x18279), FixedSizeArray] internal FixedSizeArray55<byte> _unlockedTripleTriadCardsBitmask;
    [FieldOffset(0x182B0)] public ulong UnlockedTripleTriadCardsCount;

    [FieldOffset(0x182CA)] public float TerritoryTypeTransientOffsetZ; // TODO: this is a short in the sheet and copied with a 4 byte register??

    [FieldOffset(0x182CE)] public byte BeginnerGuideFlags;
    [FieldOffset(0x182CF)] public byte BattleEffectSelf;
    [FieldOffset(0x182D0)] public byte BattleEffectParty;
    [FieldOffset(0x182D1)] public byte BattleEffectOther;

    [FieldOffset(0x182D3)] public byte BattleEffectPvPEnemyPc;

    [FieldOffset(0x182D8)] public uint UnlockedCompanionsCount;

    [FieldOffset(0x184C9)] public bool TerritoryTypeTransientRowLoaded;

    [FieldOffset(0x184CB)] public byte GMRank;

    [FieldOffset(0x18540)] public Utf8String JournalDetailDescription;

    [MemberFunction("E8 ?? ?? ?? ?? 3C 01 74 23")]
    public partial bool IsUnlockLinkUnlocked(uint unlockLink);

    /// <summary>
    /// Checks to see if an unlock link is unlocked, or if the passed value is greater than 0x10000, checks if the quest
    /// is completed.
    /// </summary>
    /// <param name="unlockLinkOrQuestId">The unlock link or quest ID to check.</param>
    /// <param name="minQuestProgression">If the quest is not complete, check for <em>at least</em> this level of
    /// progress in the quest (using <see cref="QuestManager.GetQuestSequence(ushort)"/>. If this parameter is <c>0</c>,
    /// the quest must have been completed.</param>
    /// <param name="a4">Exact purpose unknown, but appears to be a flag to respect Unlock Flag 245 (ignore quest
    /// progression?) for quest-based checks. Virtually always <c>true</c> in game code.</param>
    /// <returns>Returns true if the unlock link is unlocked or if the quest is completed.</returns>
    [MemberFunction("E8 ?? ?? ?? ?? 84 C0 74 A2")]
    public partial bool IsUnlockLinkUnlockedOrQuestCompleted(uint unlockLinkOrQuestId, byte minQuestProgression = 0, bool a4 = true);

    /// <summary>
    /// Check an item (by EXD row) to see if the action associated with the item is unlocked or "obtained/registered."
    /// </summary>
    /// <remarks>
    /// This method <b>will</b> call EXD, so the usual caveats there apply. Where possible, use a by-ID check as
    /// they're generally faster and/or rely less on EXD.
    /// </remarks>
    /// <param name="itemExdPtr">A pointer to an EXD row for an item, generally retrieved from <see cref="ExdModule.GetItemRowById"/>.</param>
    /// <returns>Returns a value denoting this item's unlock status from the below table:
    /// <list type="table">
    /// <listheader><term>Value</term><description>Meaning</description></listheader>
    /// <item><term>1</term><description>The item is unlocked/registered.</description></item>
    /// <item><term>2</term><description>The item is not unlocked/registered, but can be.</description></item>
    /// <item><term>3</term><description>Unknown, possibly "information not loaded yet."</description></item>
    /// <item><term>4</term><description>The item does not have an unlock status.</description></item>
    /// </list>
    /// </returns>
    [MemberFunction("E8 ?? ?? ?? ?? 49 8B CE 89 86")]
    public partial long IsItemActionUnlocked(void* itemExdPtr);

    /// <summary>
    /// Check if a Triple Triad card is obtained by the character.
    /// </summary>
    /// <param name="cardId">The ID of the card (technically, of TripleTriadCardResident) to check against.</param>
    /// <returns>Returns true if the card is unlocked.</returns>
    [MemberFunction("E9 ?? ?? ?? ?? 48 85 DB 74 03")]
    public partial bool IsTripleTriadCardUnlocked(ushort cardId);

    /// <summary>
    /// Check if an emote (by ID) is unlocked.
    /// </summary>
    /// <remarks>
    /// This method *will* perform an EXD get. If the unlock link is known it is better to call
    /// <see cref="IsUnlockLinkUnlockedOrQuestCompleted"/> in order to prevent the extra call, as it performs
    /// functionally the same checks.
    /// </remarks>
    /// <param name="emoteId">The ID of the emote to check for.</param>
    /// <returns>Returns true if the emote is unlocked.</returns>
    [MemberFunction("E9 ?? ?? ?? ?? 8B 13 41 B8 ?? ?? ?? ?? 8B CA")]
    public partial bool IsEmoteUnlocked(ushort emoteId);

    /// <summary>
    /// Check if a aetheryte is unlocked for the current character.
    /// </summary>
    /// <param name="aetheryteId">The ID of the aetheryte to check for.</param>
    /// <returns>Returns true if the specified aetheryte is unlocked.</returns>
    public bool IsAetheryteUnlocked(uint aetheryteId) {
        return ((1 << ((int)aetheryteId & 7)) & UnlockedAetherytesBitmask[(int)aetheryteId / 8]) > 0;
    }

    /// <summary>
    /// Check if a HowTo is unlocked for the current character.
    /// </summary>
    /// <param name="howtoId">The ID of the HowTo to check for.</param>
    /// <returns>Returns true if the specified HowTo is unlocked.</returns>
    public bool IsHowToUnlocked(uint howtoId) {
        return ((1 << ((int)howtoId & 7)) & UnlockedHowtoBitmask[(int)howtoId / 8]) > 0;
    }

    /// <summary>
    /// Check if a companion (minion) is unlocked for the current character.
    /// </summary>
    /// <param name="companionId">The ID of the companion/minion to check for.</param>
    /// <returns>Returns true if the specified minion is unlocked.</returns>
    public bool IsCompanionUnlocked(uint companionId) {
        return ((1 << ((int)companionId & 7)) & UnlockedCompanionsBitmask[(int)companionId / 8]) > 0;
    }

    public bool IsChocoboTaxiStandUnlocked(uint chocoboTaxiStandId) {
        return ((1 << ((ushort)chocoboTaxiStandId & 7)) & ChocoboTaxiStandsBitmask[(ushort)chocoboTaxiStandId / 8]) > 0;
    }

    [MemberFunction("E8 ?? ?? ?? ?? 88 46 02 B0 01")]
    public static partial bool IsInstanceContentCompleted(uint instanceContentId);

    [MemberFunction("E8 ?? ?? ?? ?? 3C 01 75 38")]
    public static partial bool IsInstanceContentUnlocked(uint instanceContentId);

    [MemberFunction("48 83 EC 28 E8 ?? ?? ?? ?? 48 85 C0 74 14 0F B7 40 2A")]
    public static partial bool IsPublicContentCompleted(uint publicContentId);

    [MemberFunction("E9 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 24 01")]
    public static partial bool IsPublicContentUnlocked(uint publicContentId);

    /// <summary> Check if the player has seen the cutscene before. </summary>
    /// <remarks>
    /// Only tracks skippable cutscenes (for that, check if WorkIndex is not 0 in CutsceneWorkIndex sheet).
    /// </remarks>
    /// <param name="cutsceneId"> RowId of the Cutscene </param>
    /// <returns> Returns <c>true</c> if the player has seen the cutscene before, otherwise <c>false</c>. </returns>
    [MemberFunction("E8 ?? ?? ?? ?? 33 D2 0F B6 CB 3A C3")]
    public partial bool IsCutsceneSeen(uint cutsceneId);

    /// <remarks>Requests timestamps for <see cref="NextMapAllowanceTimestamp"/> and <see cref="NextChallengeLogResetTimestamp"/>.</remarks>
    [MemberFunction("48 83 EC 38 48 C7 81")]
    public partial bool RequestResetTimestamps();

    [MemberFunction("E8 ?? ?? ?? ?? 48 8B F8 E8 ?? ?? ?? ?? 8D 48 05")]
    public partial long GetNextMapAllowanceTimestamp();

    public DateTime GetNextMapAllowanceDateTime() {
        var timeStamp = GetNextMapAllowanceTimestamp();
        return timeStamp > 0 ? DateTime.UnixEpoch.AddSeconds(timeStamp) : DateTime.MinValue;
    }

    [MemberFunction("E8 ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ?? 44 8B C8")]
    public partial long GetNextChallengeLogResetTimestamp();

    public DateTime GetNextChallengeLogResetDateTime() {
        var timeStamp = GetNextChallengeLogResetTimestamp();
        return timeStamp > 0 ? DateTime.UnixEpoch.AddSeconds(timeStamp) : DateTime.MinValue;
    }
}
