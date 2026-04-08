Add-Type -AssemblyName System.Numerics

$email = "admin@"
$password = "admin@"
$battletag = "admin"
$userlevel = "Owner"

# SHA256
$sha = [System.Security.Cryptography.SHA256]::Create()

# Generate 32-byte salt
$salt = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($salt)

# N (from SRP6a)
$NHex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
# Convert hex to BigInteger (need to prepend 00 for positive)
$NBytes = [byte[]]::new($NHex.Length / 2 + 1)
for ($i = 0; $i -lt $NHex.Length; $i += 2) {
    $NBytes[$NHex.Length / 2 - 1 - $i/2] = [Convert]::ToByte($NHex.Substring($i, 2), 16)
}
$NBytes[$NBytes.Length - 1] = 0
$N = [System.Numerics.BigInteger]::new($NBytes)
$g = [System.Numerics.BigInteger]::new(2)

# identitySalt = H(email).ToHexString()
$emailBytes = [System.Text.Encoding]::ASCII.GetBytes($email)
$identitySaltBytes = $sha.ComputeHash($emailBytes)
$identitySalt = [BitConverter]::ToString($identitySaltBytes).Replace("-", "")

# pBytes = H(identitySalt.ToUpper() + ":" + password.ToUpper())
$pInput = [System.Text.Encoding]::ASCII.GetBytes($identitySalt.ToUpper() + ":" + $password.ToUpper())
$pBytes = $sha.ComputeHash($pInput)

# x = H(salt + pBytes) as little-endian BigInteger
$xInput = New-Object byte[] ($salt.Length + $pBytes.Length)
[Array]::Copy($salt, 0, $xInput, 0, $salt.Length)
[Array]::Copy($pBytes, 0, $xInput, $salt.Length, $pBytes.Length)
$xHash = $sha.ComputeHash($xInput)

# BigInteger from little-endian bytes (unsigned - add 0 byte)
$xPadded = New-Object byte[] ($xHash.Length + 1)
[Array]::Copy($xHash, 0, $xPadded, 0, $xHash.Length)
$x = [System.Numerics.BigInteger]::new($xPadded)

# v = g^x mod N
$v = [System.Numerics.BigInteger]::ModPow($g, $x, $N)
$vArray = $v.ToByteArray()

# Pad to 128 bytes
$result = New-Object byte[] 128
$copyLen = [Math]::Min($vArray.Length, 128)
[Array]::Copy($vArray, 0, $result, 0, $copyLen)

# Format as PostgreSQL bytea hex
$saltHex = "\x" + [BitConverter]::ToString($salt).Replace("-", "").ToLower()
$vHex = "\x" + [BitConverter]::ToString($result).Replace("-", "").ToLower()

# Generate SQL
$sql = @"
INSERT INTO accounts (id, email, salt, passwordverifier, battletagname, hashcode, userlevel, banned, hasrename, renamecooldown, money, discordid)
VALUES (
  (SELECT COALESCE(MAX(id), 0) + 1 FROM accounts),
  '$email',
  E'$saltHex',
  E'$vHex',
  '$battletag',
  1001,
  '$userlevel',
  false, false, 0, 0, 0
);
INSERT INTO game_accounts (id, dbaccount_id, paragonlevel, paragonlevelhardcore, experience, experiencehardcore, gold, hardcoregold, platinum, hardplatinum, rmtcurrency, hardrmtcurrency, bloodshards, hardcorebloodshards, stashsize, hardcorestashsize, seasonstashsize, hardseasonstashsize, eliteskilled, hardeliteskilled, totalkilled, hardtotalkilled, totalgold, hardtotalgold, totalbloodshards, hardtotalbloodshards, totalbounties, totalbountieshardcore, pvptotalkilled, hardpvptotalkilled, pvptotalwins, hardpvptotalwins, pvptotalgold, hardpvptotalgold, craftitem1, hardcraftitem1, craftitem2, hardcraftitem2, craftitem3, hardcraftitem3, craftitem4, hardcraftitem4, craftitem5, hardcraftitem5, bigportalkey, hardbigportalkey, leorikkey, hardleorikkey, vialofputridness, hardvialofputridness, idolofterror, hardidolofterror, heartoffright, hardheartoffright, horadrica1, hardhoradrica1, horadrica2, hardhoradrica2, horadrica3, hardhoradrica3, horadrica4, hardhoradrica4, horadrica5, hardhoradrica5, flags)
VALUES (
  (SELECT COALESCE(MAX(id), 0) + 1 FROM game_accounts),
  (SELECT id FROM accounts WHERE email = '$email'),
  0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
);
"@

# Execute directly via docker exec
$sql1 = "INSERT INTO accounts (id, email, salt, passwordverifier, battletagname, hashcode, userlevel, banned, hasrename, renamecooldown, money, discordid) VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM accounts), '$email', E'$saltHex', E'$vHex', '$battletag', 1001, '$userlevel', false, false, 0, 0, 0);"

$sql2 = "INSERT INTO game_accounts (id, dbaccount_id, paragonlevel, paragonlevelhardcore, experience, experiencehardcore, gold, hardcoregold, platinum, hardplatinum, rmtcurrency, hardrmtcurrency, bloodshards, hardcorebloodshards, stashsize, hardcorestashsize, seasonstashsize, hardseasonstashsize, eliteskilled, hardeliteskilled, totalkilled, hardtotalkilled, totalgold, hardtotalgold, totalbloodshards, hardtotalbloodshards, totalbounties, totalbountieshardcore, pvptotalkilled, hardpvptotalkilled, pvptotalwins, hardpvptotalwins, pvptotalgold, hardpvptotalgold, craftitem1, hardcraftitem1, craftitem2, hardcraftitem2, craftitem3, hardcraftitem3, craftitem4, hardcraftitem4, craftitem5, hardcraftitem5, bigportalkey, hardbigportalkey, leorikkey, hardleorikkey, vialofputridness, hardvialofputridness, idolofterror, hardidolofterror, heartoffright, hardheartoffright, horadrica1, hardhoradrica1, horadrica2, hardhoradrica2, horadrica3, hardhoradrica3, horadrica4, hardhoradrica4, horadrica5, hardhoradrica5, flags) VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM game_accounts), (SELECT id FROM accounts WHERE email = '$email'), 0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);"

Write-Host "Inserindo conta..."
& docker exec diiis-na-db psql -U postgres -d diiis -c $sql1
Write-Host "Inserindo game account..."
& docker exec diiis-na-db psql -U postgres -d diiis -c $sql2
Write-Host "Conta admin@ criada com sucesso!"
