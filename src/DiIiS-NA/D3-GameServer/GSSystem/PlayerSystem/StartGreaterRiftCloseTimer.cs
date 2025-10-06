using bgs.protocol.channel.v1;
using DiIiS_NA.Core.Logging;
using DiIiS_NA.D3_GameServer.Core.Types.SNO;
using DiIiS_NA.GameServer.ClientSystem;
using DiIiS_NA.GameServer.Core.Types.TagMap;
using DiIiS_NA.GameServer.GSSystem.ActorSystem;
using DiIiS_NA.GameServer.GSSystem.MapSystem;
using DiIiS_NA.GameServer.GSSystem.TickerSystem;
using DiIiS_NA.GameServer.MessageSystem;
using DiIiS_NA.GameServer.MessageSystem.Message.Definitions.ACD;
using DiIiS_NA.GameServer.MessageSystem.Message.Definitions.Game;
using DiIiS_NA.GameServer.MessageSystem.Message.Definitions.Quest;
using DiIiS_NA.GameServer.MessageSystem.Message.Fields;
using DiIiS_NA.LoginServer.Battle;
using Microsoft.CodeAnalysis;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DiIiS_NA.GameServer.GSSystem.PlayerSystem
{
    public static class GreaterRiftManager
    {
        private static readonly Logger logger = LogManager.CreateLogger(nameof(GreaterRiftManager));
        private static readonly ConcurrentDictionary<int, CancellationTokenSource> _riftTimers = new ConcurrentDictionary<int, CancellationTokenSource>();

        public static void StartGreaterRiftCloseTimer(World world, Portal portal, Actor lootRunObelisk, World nephalemPWorld, float durationInSeconds = 15f)
        {
            if (world == null || portal == null || lootRunObelisk == null || nephalemPWorld == null)
            {
                logger.Warn("One or more required instances are null in StartGreaterRiftCloseTimer.");
                return;
            }

            // Use the first player ID as the key.
            int playerID = (int)world.Players.Keys.First();
            logger.Info($"Starting Greater Rift close timer for {durationInSeconds} seconds in playerID: {playerID}.");

            // Remove and cancel the previous timer for this playerID, if it exists.
            if (_riftTimers.TryRemove(playerID, out var oldCancellationTokenSource))
            {
                oldCancellationTokenSource.Cancel();
                oldCancellationTokenSource.Dispose();
                logger.Info($"Cancelled previous timer for playerID: {playerID}.");
            }

            var cancellationTokenSource = new CancellationTokenSource();
            _riftTimers.TryAdd(playerID, cancellationTokenSource);

            // Start notification and closing logic.
            Task.Run(async () =>
            {
                float timeRemaining = durationInSeconds;
                bool sentInitialMessage = false;
                var playersInRift = world.Game.Players.Values;

                while (timeRemaining > 0 && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    // Send initial message once.
                    if (!sentInitialMessage)
                    {
                        string initialTimeText = FormatTime(timeRemaining);
                        //var playersInRift = world.Game.Players.Values.Where(p => p.World == nephalemPWorld);
                        foreach (var plr in playersInRift)
                        {
                            PlayerManager.SendWhisper($"Good luck, you have {initialTimeText} to finish this GR :)");
                        }
                        sentInitialMessage = true;
                    }

                    // Send message approximately every minute.
                    if (timeRemaining % 60 < 1 && timeRemaining > 30) 
                    {
                        string timeText = FormatTime(timeRemaining);
                        //var playersInRift = world.Game.Players.Values.Where(p => p.World == nephalemPWorld);
                        foreach (var plr in playersInRift)
                        {
                            PlayerManager.SendWhisper($"Reminder: you have {timeText} left to finish this GR :)");
                        }
                    }

                    // Send a message every 5 seconds when less than 30 seconds remain.
                    if (timeRemaining <= 30 && timeRemaining % 5 < 1)
                    {
                        string timeText = FormatTime(timeRemaining);
                        // var playersInRift = world.Game.Players.Values.Where(p => p.World == nephalemPWorld);
                        foreach (var plr in playersInRift)
                        {
                            PlayerManager.SendWhisper($"Hurry up! You have {timeText} left to finish this GR!!!");
                        }
                    }

                    // Wait 1 second.
                    await Task.Delay(1000, cancellationTokenSource.Token);
                    // Ensure that it does not become negative.
                    timeRemaining = Math.Max(0, timeRemaining - 1);
                }

                // Execute the closing logic when timeRemaining reaches 0.
                if (!cancellationTokenSource.Token.IsCancellationRequested)
                {
                    logger.Info($"Greater Rift close timer triggered for token id: {playerID}.");

                    // Destroy monsters.
                    if (nephalemPWorld != null)
                    {
                        foreach (var actor in nephalemPWorld.Actors.Values)
                        {
                            if (actor is Monster)
                            {
                                actor.Destroy();
                                logger.Info($"Destroyed monster: {actor.SNO} token id: {playerID}.");
                            }
                        }
                    }
                    else
                    {
                        logger.Warn($"nephalemPWorld is null in token id: {playerID}, skipping monster destruction.");
                    }

                    // Destroy portal.
                    if (portal != null)
                    {
                        portal.Destroy();
                        logger.Info($"Destroyed Greater Rift portal in token id: {playerID}.");
                    }
                    else
                    {
                        logger.Warn($"Portal is null in token id: {playerID}, skipping destruction.");
                    }

                    // Reset game state.
                    world.Game.ActiveNephalemPortal = false;
                    world.Game.NephalemGreater = false;
                    world.Game.WorldOfPortalNephalem = WorldSno.__NONE;

                    // Move players to hub.
                    var hubWorld = world.Game.GetWorld(WorldSno.x1_tristram_adventure_mode_hub);
                    if (hubWorld != null)
                    {
                        var startingPoint = hubWorld.GetStartingPointById(24);
                        //var playersInRift = world.Game.Players.Values.Where(p => p.World == nephalemPWorld);
                        foreach (var plr in playersInRift)
                        {
                            plr.ChangeWorld(hubWorld, startingPoint.Position);
                            PlayerManager.SendWhisper($"Your GR is finished!!!");
                            logger.Info($"Teleported player {plr.Toon.Name} to hub from token id: {playerID}.");
                        }
                    }
                    else
                    {
                        logger.Warn($"Hub world (x1_tristram_adventure_mode_hub) not found for token id: {playerID}.");
                    }

                    foreach (var plr in playersInRift)
                    {
                        plr.InGameClient.SendMessage(new QuestUpdateMessage
                        {
                            snoQuest = 337492,
                            snoLevelArea = 0x000466E2,
                            StepID = -1,
                            DisplayButton = false,
                            Failed = false
                        });

                        plr.InGameClient.SendMessage(new GameSyncedDataMessage
                        {
                            SyncedData = new GameSyncedData
                            {
                                GameSyncedFlags = 6,
                                Act = 3000,
                                InitialMonsterLevel = world.Game.InitialMonsterLevel,
                                MonsterLevel = 0x64E4425E,
                                RandomWeatherSeed = world.Game.WeatherSeed,
                                OpenWorldMode = -1,
                                OpenWorldModeAct = -1,
                                OpenWorldModeParam = -1,
                                OpenWorldTransitionTime = 0x00000064,
                                OpenWorldDefaultAct = 100,
                                OpenWorldBonusAct = -1,
                                SNODungeonFinderLevelArea = 0x00000001,
                                LootRunOpen = -1,
                                OpenLootRunLevel = 0,
                                LootRunBossDead = 0,
                                HunterPlayerIdx = 0,
                                LootRunBossActive = -1,
                                TieredLootRunFailed = 0,
                                LootRunChallengeCompleted = 0,
                                SetDungeonActive = 0,
                                Pregame = 0,
                                PregameEnd = 0,
                                RoundStart = 0,
                                RoundEnd = 0,
                                PVPGameOver = 0x0,
                                field_v273 = 0x0,
                                TeamWins = new[] { 0x0, 0x0 },
                                TeamScore = new[] { 0x0, 0x0 },
                                PVPGameResult = new[] { 0x0, 0x0 },
                                PartyGuideHeroId = 0x0,
                                TiredRiftPaticipatingHeroID = new long[] { 0x0, 0x0, 0x0, 0x0 }
                            }
                        });
                    }

                    // Reset obelisk state.
                    if (lootRunObelisk != null)
                    {
                        lootRunObelisk.PlayAnimation(5, (AnimationSno)lootRunObelisk.AnimationSet.TagMapAnimDefault[AnimationSetKeys.Closing]);
                        lootRunObelisk.Attributes[GameAttributes.Team_Override] = true ? -1 : 2;
                        lootRunObelisk.Attributes[GameAttributes.Untargetable] = false;
                        lootRunObelisk.Attributes[GameAttributes.NPC_Is_Operatable] = true;
                        lootRunObelisk.Attributes[GameAttributes.Operatable] = true;
                        lootRunObelisk.Attributes[GameAttributes.Operatable_Story_Gizmo] = true;
                        lootRunObelisk.Attributes[GameAttributes.Disabled] = false;
                        lootRunObelisk.Attributes[GameAttributes.Immunity] = false;
                        lootRunObelisk.Attributes.BroadcastChangedIfRevealed();

                        lootRunObelisk.CollFlags = 0;
                        world.BroadcastIfRevealed(plr => new ACDCollFlagsMessage
                        {
                            ActorID = lootRunObelisk.DynamicID(plr),
                            CollFlags = 0
                        }, lootRunObelisk);
                        logger.Info("Obelisk state reset.");
                    }
                    else
                    {
                        logger.Warn("lootRunObelisk is null, skipping reset.");
                    }

                    logger.Info($"Greater Rift closed after {durationInSeconds} seconds in token id: {playerID}, obelisk reset for new rift.");
                }
            }, cancellationTokenSource.Token);
        }

        private static string FormatTime(float seconds)
        {
            // Avoid negative values.
            if (seconds < 0) return "0 seconds";
            if (seconds < 60)
            {
                return $"{seconds:F0} second{(seconds == 1 ? "" : "s")}";
            }
            else
            {
                float minutes = seconds / 60f;
                // Int to avoi 1.0, show just 1 min.
                if (minutes == (int)minutes) 
                {
                    return $"{(int)minutes} minute{(minutes == 1 ? "" : "s")}";
                }
                return $"{minutes:F1} minute{(minutes == 1 ? "" : "s")}";
            }
        }
    }
}
