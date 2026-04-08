#!/bin/bash
# Generate SRP6a password verifier inside the container and insert into DB

# This script runs inside a container with dotnet available
cat > /tmp/CreateAdmin.csx << 'CSHARPEOF'
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

var email = "admin@";
var password = "admin@";

var H = SHA256.Create();
var rng = RandomNumberGenerator.Create();

// Generate salt
var salt = new byte[32];
rng.GetBytes(salt);

// N and g from SRP6a
var N = BigInteger.Parse("00EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", System.Globalization.NumberStyles.HexNumber);
var g = new BigInteger(2);

// Calculate password verifier
var identitySalt = BitConverter.ToString(H.ComputeHash(Encoding.ASCII.GetBytes(email))).Replace("-", "");
var pBytes = H.ComputeHash(Encoding.ASCII.GetBytes(identitySalt.ToUpper() + ":" + password.ToUpper()));
var xBytes = new byte[salt.Length + pBytes.Length];
Buffer.BlockCopy(salt, 0, xBytes, 0, salt.Length);
Buffer.BlockCopy(pBytes, 0, xBytes, salt.Length, pBytes.Length);
var xHash = H.ComputeHash(xBytes);

// Convert to BigInteger (little-endian, unsigned)
var xHashPadded = new byte[xHash.Length + 1]; // extra 0 byte for unsigned
Buffer.BlockCopy(xHash, 0, xHashPadded, 0, xHash.Length);
var x = new BigInteger(xHashPadded);

var v = BigInteger.ModPow(g, x, N);
var vBytes = v.ToByteArray();
// Pad or trim to 128 bytes
var result = new byte[128];
Buffer.BlockCopy(vBytes, 0, result, 0, Math.Min(vBytes.Length, 128));

// Output hex for psql
Console.WriteLine("\\\\x" + BitConverter.ToString(salt).Replace("-", "").ToLower());
Console.WriteLine("\\\\x" + BitConverter.ToString(result).Replace("-", "").ToLower());
CSHARPEOF

dotnet script /tmp/CreateAdmin.csx 2>/dev/null
