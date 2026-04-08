INSERT INTO accounts (id, email, salt, passwordverifier, battletagname, hashcode, userlevel, banned, hasrename, renamecooldown, money, discordid)
VALUES (
  (SELECT COALESCE(MAX(id), 0) + 1 FROM accounts),
  'admin@',
  E'\x6ceb67a09b7dc8a65c3a350f2740e3aae60da7642d1cae2eb9708dbb17d3666b',
  E'\x84cdcf6cac6d387536ae3c13c6abfe4b68917934b97f9d06e2a923be193c80163f6b749bb47fb8d0373a624d5bc0ff9cf8c18176f079f78b45fc45ce9d319ba94e6e9f69761779b714df2b17a46ef03d63e945a46edbac579cdf1783342a4b89b2b1604e426c82ea6592bc1d9bc35879404acf13ae5897f66d3e3ed60720f372',
  'admin',
  1001,
  'Owner',
  false, false, 0, 0, 0
);
INSERT INTO game_accounts (id, dbaccount_id, paragonlevel, paragonlevelhardcore, experience, experiencehardcore, gold, hardcoregold, platinum, hardplatinum, rmtcurrency, hardrmtcurrency, bloodshards, hardcorebloodshards, stashsize, hardcorestashsize, seasonstashsize, hardseasonstashsize, eliteskilled, hardeliteskilled, totalkilled, hardtotalkilled, totalgold, hardtotalgold, totalbloodshards, hardtotalbloodshards, totalbounties, totalbountieshardcore, pvptotalkilled, hardpvptotalkilled, pvptotalwins, hardpvptotalwins, pvptotalgold, hardpvptotalgold, craftitem1, hardcraftitem1, craftitem2, hardcraftitem2, craftitem3, hardcraftitem3, craftitem4, hardcraftitem4, craftitem5, hardcraftitem5, bigportalkey, hardbigportalkey, leorikkey, hardleorikkey, vialofputridness, hardvialofputridness, idolofterror, hardidolofterror, heartoffright, hardheartoffright, horadrica1, hardhoradrica1, horadrica2, hardhoradrica2, horadrica3, hardhoradrica3, horadrica4, hardhoradrica4, horadrica5, hardhoradrica5, flags)
VALUES (
  (SELECT COALESCE(MAX(id), 0) + 1 FROM game_accounts),
  (SELECT id FROM accounts WHERE email = 'admin@'),
  0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
);
