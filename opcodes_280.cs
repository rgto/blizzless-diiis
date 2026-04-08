// D3 2.8.0 (build 99920) Wire Protocol Opcodes
// Extracted from Diablo III64.exe via Ghidra 12.0.4
// 155 opcodes (0-154), confirmed by CMP EDX,0x9B bounds check
// Wire format: 10-bit opcode followed by message payload
// Sources: type table at 0x1414051F8, accessor functions at 0x1408A6xxx-0x1408A8xxx

// SIZE key:
//   Specific number = extracted from inline accessor function
//   16 = default from JMP epilogue (0x1408A8874)
//   ? = no accessor found (likely sub-structure, not a direct wire message)

#region 2.8.0
        SetDungeonMessage = 0, //SIZE ?
        EncounterInviteStateMessage = 1, //SIZE 12
        RiftStartAcceptedMessage = 2, //SIZE 16
        RiftJoinMessage = 3, //SIZE 20
        DebugDrawPrimMessage = 4, //SIZE 188
        DebugDrawMovementTypeMessage = 5, //SIZE 144
        CameraZoomMessage = 6, //SIZE 20
        CameraYawMessage = 7, //SIZE 20
        BossZoomMessage = 8, //SIZE 16
        PlayCutsceneMessage = 9, //SIZE 12
        PlayerWarpedMessage = 10, //SIZE 16
        DebugActorTooltipMessage = 11, //SIZE 1036
        SalvageResultsMessage = 12, //SIZE 56
        TrySalvageAllMessage = 13, //SIZE 12
        GameTestingWorldSamplingStartMessage = 14, //SIZE 16
        GameTestingSkillSamplingStartMessage = 15, //SIZE 16
        RequestBuffCancelMessage = 16, //SIZE 16
        PlayErrorSoundMessage = 17, //SIZE 12
        HirelingRequestLearnSkillMessage = 18, //SIZE 16
        LogoutTickTimeMessage = 19, //SIZE 24
        VersionsMessage = 20, //SIZE 48
        HandicapMessage = 21, //SIZE 12
        PlayerSetCameraObserverMessage = 22, //SIZE 32
        PlayerSetCameraOrbitMessage = 23, //SIZE 24
        PlayerSetCameraDefaultsMessage = 24, //SIZE 8
        OpenWorldModeChangeMessage = 25, //SIZE 20
        PlayerClearClientWalkPowerMessage = 26, //SIZE 16
        ActorLookOverrideChangedMessage = 27, //SIZE 20
        PortedToPlayerMessage = 28, //SIZE 16
        PortedToWaypointMessage = 29, //SIZE 16
        ItemJunkFlagChangedMessage = 30, //SIZE 16
        AchievementProgressXboxOneMessage = 31, //SIZE 20
        ConsoleCounterIncrementMessage = 32, //SIZE 16
        ServerNotificationDataMessage = 33, //SIZE 16
        JewelUpgradeResultsMessage = 34, //SIZE 16
        DungeonFinderClosingMessage = 35, //SIZE 16
        UberBosssClosingMessage = 36, //SIZE 16
        WarningCountdownNotificationMessage = 37, //SIZE 268
        BlizzconEndScreenMessage = 38, //SIZE 16
        HoradricQuestCursedRealmResults = 39, //SIZE 16
        SetDungeonDialogMessage = 40, //SIZE 20
        FirstOfTheDayMessage = 41, //SIZE 32
        PlatinumAwardedMessage = 42, //SIZE 24
        PlatinumAchievementAwardedMessage = 43, //SIZE 32
        SetDungeonResultsMessage = 44, //SIZE 56
        DungeonFinderCompletionTimeMessage = 45, //SIZE 16
        InvLoc = 46, //SIZE ? (sub-structure)
        RequiredMessageHeader = 47, //SIZE ? (sub-structure)
        InventoryRequestMoveMessage = 48, //SIZE 28
        InventorySplitStackMessage = 49, //SIZE 40
        InventoryRequestQuickMoveMessage = 50, //SIZE 28
        SimpleMessage = 51, //SIZE 8
        GenericBlobMessage = 52, //SIZE 12
        ChunkMessage = 53, //SIZE 16
        BoolDataMessage = 54, //SIZE 12
        ByteDataMessage = 55, //SIZE ? (sub-structure)
        PlayerIndexMessage = 56, //SIZE 12
        DataIDDataMessage = 57, //SIZE 12
        DWordDataMessage = 58, //SIZE 12
        PlayerDWordDataMessage = 59, //SIZE 16
        PlayerDWord2DataMessage = 60, //SIZE 20
        IntDataMessage = 61, //SIZE 12
        Int64DataMessage = 62, //SIZE ? (sub-structure)
        UInt64DataMessage = 63, //SIZE ? (sub-structure)
        FloatDataMessage = 64, //SIZE 12
        SNODataMessage = 65, //SIZE 12
        SNONameDataMessage = 66, //SIZE 16
        PreloadACDDataMessage = 67, //SIZE 52
        PrefetchActorDataMessage = 68, //SIZE 44
        GBIDDataMessage = 69, //SIZE 12
        DisplayGameTextMessage = 70, //SIZE 1048
        ANNDataMessage = 71, //SIZE 12
        JoinLANGameMessage = 72, //SIZE 196
        JoinConsoleGameMessage = 73, //SIZE 20
        BroadcastTextMessage = 74, //SIZE 1032
        QuitGameMessage = 75, //SIZE 12
        ConnectionEstablishedMessage = 76, //SIZE 20
        GameSetupMessage = 77, //SIZE 12
        EnterKnownLookOverrides = 78, //SIZE ? (sub-structure)
        EnterWorldMessage = 79, //SIZE 60
        RevealWorldMessage = 80, //SIZE 44
        WorldLocationMessageData = 81, //SIZE ? (sub-structure)
        InventoryLocationMessageData = 82, //SIZE ? (sub-structure)
        ACDEnterKnownMessage = 83, //SIZE 168
        PlayerEnterKnownMessage = 84, //SIZE 16
        ACDInventoryPositionMessage = 85, //SIZE 32
        ACDInventoryUpdateActorSNO = 86, //SIZE 16
        ACDWorldPositionMessage = 87, //SIZE 76
        ACDShearMessage = 88, //SIZE 16
        ACDGroupMessage = 89, //SIZE 20
        ACDChangeActorMessage = 90, //SIZE 16
        ACDPickupFailedMessage = 91, //SIZE 20
        AffixMessage = 92, //SIZE 148
        ProjectileStickMessage = 93, //SIZE 28
        PlayerActorSetInitialMessage = 94, //SIZE 16
        AnimPreplayData = 95, //SIZE ? (sub-structure)
        TargetMessage = 96, //SIZE 76
        SecondaryAnimationPowerMessage = 97, //SIZE 32
        LoopingAnimationPowerMessage = 98, //SIZE 20
        TryConsoleCommand = 99, //SIZE 1060
        TryChatMessage = 100, //SIZE 1040
        ChatMessage = 101, //SIZE 1040
        VoteKickMessage = 102, //SIZE 1040
        VictimMessage = 103, //SIZE 44
        LootRunAppearedMessage = 104, //SIZE 12
        CombatEngagementMessage = 105, //SIZE 28
        DuelResultMessage = 106, //SIZE 20
        KillCountMessage = 107, //SIZE 24
        StackPortionMessage = 108, //SIZE 24
        CurrencyMessage = 109, //SIZE ? (sub-structure)
        ChangeUsableItemMessage = 110, //SIZE 16
        InventoryStackTransferMessage = 111, //SIZE 24
        GoldTransferMessage = 112, //SIZE 24
        InventoryRequestSocketMessage = 113, //SIZE 16
        InventoryRequestUseMessage = 114, //SIZE 36
        HelperDetachMessage = 115, //SIZE 12
        PetMessage = 116, //SIZE 24
        PetDetachMessage = 117, //SIZE 16
        FlippyMessage = 118, //SIZE 32
        ComplexEffectAddMessage = 119, //SIZE 40
        PlayerLevel = 120, //SIZE 16
        AimTargetMessage = 121, //SIZE 36
        ACDChangeGBHandleMessage = 122, //SIZE 20
        TrickleMessage = 123, //SIZE 188
        PlayerIntValMessage = 124, //SIZE 16
        UIElementMessage = 125, //SIZE 16
        PlasmaAttachMessage = 126, //SIZE ? (sub-structure)
        RitualTetherEffectMessage = 127, //SIZE ? (sub-structure)
        RevealTeamMessage = 128, //SIZE 20
        DeathFadeTimeMessage = 129, //SIZE 24
        MapRevealSceneMessage = 130, //SIZE 52
        SavePointInfoMessage = 131, //SIZE 12
        HearthPortalInfoMessage = 132, //SIZE 28
        ReturnPointInfoMessage = 133, //SIZE 12
        ACDLookAtMessage = 134, //SIZE 16
        KillCounterUpdateMessage = 135, //SIZE 28
        CurrencyCounterUpdateMessage = 136, //SIZE 20
        LowHealthCombatMessage = 137, //SIZE 16
        SaviorMessage = 138, //SIZE 16
        FloatingNumberMessage = 139, //SIZE 20
        FloatingGBIDAmountMessage = 140, //SIZE 32
        FloatingAmountMessage = 141, //SIZE 40
        CalloutMessage = 142, //SIZE 28
        RemoveRagdollMessage = 143, //SIZE 16
        WorldStatusMessage = 144, //SIZE 16
        WaypointActivatedMessage = 145, //SIZE 24
        TryWaypointMessage = 146, //SIZE 16
        LoreMessage = 147, //SIZE 12
        PRTransformMessage = 148, //SIZE ? (sub-structure)
        WorldDeletedMessage = 149, //SIZE 12
        PlayerQuestMessage = 150, //SIZE 20
        PlayerDeSyncSnapMessage = 151, //SIZE 36
        BlizzconCVarsMessage = 152, //SIZE ? (sub-structure)
        CameraFocusMessage = 153, //SIZE 20
        TradeMessage = 154, //SIZE 56
#endregion

// === NOTES ===
// 1. This is the COMPLETE wire opcode table. D3 2.8.0 uses 155 unique message
//    types as wire opcodes, vs ~553 in 2.7.4. The generic types (SimpleMessage,
//    GenericBlobMessage, ANNDataMessage, etc.) are now single opcodes instead of
//    having many aliases.
//
// 2. In 2.7.4, SimpleMessage had ~70 different opcode aliases (LoadingWarping=12,
//    LeaveConsoleGame=19, etc.). In 2.8.0, SimpleMessage is opcode 51 only.
//    This means the server needs FUNDAMENTAL restructuring of message dispatch.
//
// 3. SIZE ? entries are likely sub-structures embedded in other messages, not
//    direct wire messages. They had no accessor function in the binary.
//
// 4. Verified: VersionsMessage=20 SIZE 48 matches 2.7.4.
//    QuitGameMessage moved from opcode 3 (2.7.4) to 75 (2.8.0).
//
// 5. New messages in 2.8.0 (not in 2.7.4):
//    - WarningCountdownNotificationMessage (37)
//    - BlizzconCVarsMessage (152)
//    - PRTransformMessage (148)
//    - RitualTetherEffectMessage (127)
//    - SetDungeonMessage (0)
//    - SetDungeonDialogMessage (40)
//    - SetDungeonResultsMessage (44)
//    - EnterKnownLookOverrides (78)
//    - and others
