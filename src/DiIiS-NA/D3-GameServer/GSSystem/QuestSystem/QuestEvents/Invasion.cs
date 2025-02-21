﻿//Blizzless Project 2022 
using DiIiS_NA.D3_GameServer.Core.Types.SNO;
using DiIiS_NA.GameServer.Core.Types.Math;
//Blizzless Project 2022 
using DiIiS_NA.GameServer.GSSystem.TickerSystem;
//Blizzless Project 2022 
using System;
//Blizzless Project 2022 
using System.Collections.Generic;
//Blizzless Project 2022 
using System.Linq;
//Blizzless Project 2022 
using System.Text;
//Blizzless Project 2022 
using System.Threading.Tasks;

namespace DiIiS_NA.GameServer.GSSystem.QuestSystem.QuestEvents
{
	class Invasion : QuestEvent
	{
		public float Radius;
		public float Duration;
		public Vector3D Center;
		public List<ActorSno> Monsters;
		public ActorSno LastMob;
		public bool LastSolo;

		public Invasion(Vector3D center, float radius, List<ActorSno> mobs, float duration, ActorSno lastMob, bool lastSolo)
			: base(0)
		{
			this.Radius = radius;
			this.Center = center;
			this.Monsters = mobs;
			this.Duration = duration;
			this.LastMob = lastMob;
			this.LastSolo = lastSolo;
		}

		public override void Execute(MapSystem.World world)
		{
			var marker = world.SpawnMonster(ActorSno._generic_proxy_normal, this.Center);
			world.BuffManager.AddBuff(marker, marker, new PowerSystem.Implementations.InvasionBuff(TickTimer.WaitSeconds(world.Game, this.Duration), this.Monsters, this.Radius, this.LastMob, this.LastSolo));
		}
	}
}
