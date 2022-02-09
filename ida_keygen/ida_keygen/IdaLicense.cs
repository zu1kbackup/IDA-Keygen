using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace ida_keygen;

enum LicenseType
{
    Fixed,
    Named,
    Computer,
    Floating
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
unsafe struct License
{
    public byte zero;
    public ushort mark;
    public ushort version;
    public ushort licType;
    public ushort numSeats;
    public ulong capabilities1;
    public uint issueDateTime;
    public uint licenseExpire;
    public uint supportExpire;
    public fixed byte licId[6];
    public fixed byte name[69];
    public ulong capabilities2;
    public fixed byte md5[16];
}

class IdaLicense
{
    public (License license, bool isPirated) Read(IEnumerable<string> keyData)
    {
        Span<byte> signatureData = new byte[160];
        Span<byte> randomData = new byte[64];

        Span<byte> signatureSpan = signatureData;

        int sigBytesWritten = 0;

        foreach (var line in keyData)
        {
            ReadOnlySpan<char> lineSpan = line;

            if (lineSpan.StartsWith("R:"))
            {
                Convert.TryFromBase64Chars(lineSpan.Slice(2), randomData, out int bytesWritten);
                ThrowHelper(bytesWritten != 57, nameof(randomData));
            }

            if (lineSpan.StartsWith("S:"))
            {
                Convert.TryFromBase64Chars(lineSpan.Slice(2), signatureSpan, out var bytesWritten);
                sigBytesWritten += bytesWritten;
                signatureSpan = signatureSpan.Slice(bytesWritten);
            }
        }

        ThrowHelper(sigBytesWritten != 160, nameof(signatureData));

        bool isPirated = false;
        Span<byte> licenseData;
        bool licenseDecrypted = DecryptLicense(signatureData, mod_rsa, out licenseData);

        if (!licenseDecrypted)
        {
            isPirated = true;
            licenseDecrypted = DecryptLicense(signatureData, mod_rsa_patched, out licenseData);
        }

        ThrowHelper(licenseDecrypted == false, nameof(licenseData));

        return (Unsafe.As<byte, License>(ref licenseData[0]), isPirated);
    }

    public (License license, bool isPirated) Read(string keyFile)
    {
        string[] keyData = File.ReadAllLines(keyFile);
        return Read(keyData);
    }

    private bool DecryptLicense(Span<byte> signatureData, ReadOnlySpan<byte> modulus, out Span<byte> licenseData)
    {
        BigInteger msg = new BigInteger(signatureData, true, false);
        BigInteger pub = new BigInteger(exp_rsa, true, false);
        BigInteger mod = new BigInteger(modulus, true, false);
        BigInteger emsg = BigInteger.ModPow(msg, pub, mod);

        licenseData = new byte[128];

        ThrowHelper(emsg.TryWriteBytes(licenseData, out int licBytesWritten, true, false) == false, nameof(licenseData));

        licenseData.Reverse();

        ref License lic = ref Unsafe.As<byte, License>(ref licenseData[0]);

        unsafe
        {
            return lic.zero == 0 && lic.licId[0] == 0x48 && lic.licType < 4 && lic.name[0] != 0 && lic.version < 2000;
        }
    }

    private void ThrowHelper(bool condition, string subj, [CallerArgumentExpression("condition")] string message = "")
    {
        if (condition)
            throw new Exception($"{subj}: {message}");
    }

    public void DisplayLicense(License lic)
    {
        Console.WriteLine($"Version: {lic.version}");
        Console.WriteLine($"Mark: {lic.mark:X4}");
        Console.WriteLine($"Cap1: {lic.capabilities1:X16}");
        Console.WriteLine($"Cap2: {lic.capabilities2:X16}");
        if (lic.issueDateTime != 0)
            Console.WriteLine($"Issue time: {DateTimeOffset.FromUnixTimeSeconds(lic.issueDateTime)}");
        if (lic.licenseExpire != 0)
            Console.WriteLine($"Expiry time: {DateTimeOffset.FromUnixTimeSeconds(lic.licenseExpire)}");
        if (lic.supportExpire != 0)
            Console.WriteLine($"Support End time: {DateTimeOffset.FromUnixTimeSeconds(lic.supportExpire)}");
        Console.WriteLine($"Type: {lic.licType} ({(LicenseType)lic.licType})");
        Console.WriteLine($"Seats: {lic.numSeats}");
        unsafe
        {
            string name = new string((sbyte*)lic.name);
            Console.WriteLine($"Name: {name}");
            Span<byte> id = new Span<byte>(lic.licId, 6);
            Console.WriteLine($"LicID: {Convert.ToHexString(id)}");
            Span<byte> md5 = new Span<byte>(lic.md5, 16);
            Console.WriteLine($"MD5: {Convert.ToHexString(md5)}");
        }
        Console.WriteLine();
    }

    private readonly (string licType, string licTypeShort)[] idaLicenses =
    {
        ("Fixed License", ""),
        ("Named License", "N"),
        ("Computer License", "C"),
        ("Floating License", "F")
    };

    private readonly (string platform, string platformShort)[] idaPlatforms =
    {
        ("Windows", "W"),
        ("Linux", "L"),
        ("Mac", "M")
    };

    private readonly (byte code, string name, string shortName)[] idaProducts =
    {
        (0x48, "IDA Professional", "IDAPRO"),
        // unknown products:
        //(0x??, "IDA Starter", "IDASTA"),
        //(0x48, "IDA Pro Advanced", "IDAADV"),
        //(0x??, "IDA Educational", "IDAEDU"),
        //(0x??, "IDA Home for Intel x64", "IDAPC"),
        //(0x??, "IDA Home for ARM", "IDAARM"),
        //(0x??, "IDA Home for PowerPC", "IDAPPC"),
        //(0x??, "IDA Home for MIPS", "IDAMIPS"),
        //(0x??, "IDA Home for Motorola 68K", "IDAM68K"),
        //(0x??, "Hex-Rays Base", "IDABASE"),
        //(0x??, "Hex-Rays Core", "IDACORE"),
        //(0x??, "Hex-Rays Ultra", "IDAULT"),
        (0x50, "MIPS Decompiler", "HEXMIPS"),
        (0x51, "MIPS64 Decompiler", "HEXMIPS64"),
        (0x52, "PowerPC64 Decompiler", "HEXPPC64"),
        (0x53, "PowerPC Decompiler", "HEXPPC"), // also 0x31?
        (0x54, "ARM64 Decompiler", "HEXARM64"), // also 0x68?
        (0x55, "x64 Decompiler", "HEXX64"),
        (0x56, "ARM Decompiler", "HEXARM"),
        (0x57, "x86 Decompiler", "HEXX86")
    };

    public (License lic, IEnumerable<string> key) GenerateNewLicense(int version, string user, string email, int numSeats, LicenseType licType, DateTimeOffset issueDateTime, int supportExpireDays = 0, int licenseExpireDays = 0)
    {
        Span<byte> licenseData = new byte[128];
        Span<byte> signatureData = new byte[160];
        Span<byte> randomData = new byte[64];

        List<string> licenseLines = new List<string>();
        licenseLines.Add($"HEXRAYS_LICENSE {version / 100}.{version % 100 / 10}");
        licenseLines.Add(string.Empty);
        licenseLines.Add($"USER            {user}");
        licenseLines.Add($"EMAIL           {email}");
        licenseLines.Add($"ISSUED_ON       {issueDateTime:yyyy-MM-dd HH:mm:ss}");
        licenseLines.Add(string.Empty);
        licenseLines.Add("  LICENSE_ID    PRODUCT     #  SUPPORT    EXPIRES        DESCRIPTION");
        licenseLines.Add("--------------- ---------- -- ---------- ---------  -----------------------------");

        DateTimeOffset supportExpireDateTime = issueDateTime.AddDays(supportExpireDays);
        DateTimeOffset licenseExpireDateTime = issueDateTime.AddDays(licenseExpireDays);

        int licenseTypeIndex = (int)licType;

        Random.Shared.NextBytes(randomData);

        License lic = new License();

        lic.mark = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(randomData) & 0x7FFF);
        lic.version = (ushort)version;
        lic.licType = (ushort)licType;
        lic.numSeats = (ushort)numSeats;
        if (issueDateTime != licenseExpireDateTime)
            lic.licenseExpire = (uint)licenseExpireDateTime.ToUnixTimeSeconds();
        if (issueDateTime != supportExpireDateTime)
            lic.supportExpire = (uint)supportExpireDateTime.ToUnixTimeSeconds();
        lic.capabilities1 = 0xFFFFFFFFFFFFFFFF;
        lic.capabilities2 = 0x7FF;
        unsafe
        {
            lic.licId[0] = 0x48;
            lic.licId[1] = randomData[0];
            lic.licId[2] = randomData[1];
            lic.licId[3] = randomData[2];
            lic.licId[4] = randomData[3];
            lic.licId[5] = randomData[4];

            Span<byte> nameSpan = new Span<byte>(lic.name, 69);
            Encoding.UTF8.GetBytes(user, nameSpan);
        }
        lic.issueDateTime = (uint)issueDateTime.ToUnixTimeSeconds();

        for (int i = 0; i < idaProducts.Length; i++)
        {
            for (int j = 0; j < idaPlatforms.Length; j++)
            {
                if (i != 0 || j > 0)
                    Random.Shared.NextBytes(randomData);

                string productId = $"{idaProducts[i].code:X2}-{randomData[0]:X2}{randomData[1]:X2}-{randomData[2]:X2}{randomData[3]:X2}-{randomData[4]:X2}";
                string productShortPart = $"{idaProducts[i].shortName}{idaLicenses[licenseTypeIndex].licTypeShort}{idaPlatforms[j].platformShort}";
                string productFullPart = $"{idaProducts[i].name} {idaLicenses[licenseTypeIndex].licType} ({idaPlatforms[j].platform})";
                string supportPart = supportExpireDays > 0 ? $"{supportExpireDateTime:yyyy-MM-dd}" : "Never"; // Never doesn't seems to work with support expire :(
                string expiresPart = licenseExpireDays > 0 ? $"{licenseExpireDateTime:yyyy-MM-dd}" : "Never";
                string licenseLine = $"{productId} {productShortPart,-10} {numSeats,2} {supportPart,-10} {expiresPart,-10} {productFullPart}";
                licenseLines.Add(licenseLine);
            }
        }

        licenseLines.Add(string.Empty);
        licenseLines.Add($"R:{Convert.ToBase64String(randomData.Slice(0, 57))}");

        MD5 md5 = new MD5();

        foreach (var line in licenseLines)
            md5.Update(line);

        Span<byte> hash = md5.Final();

        unsafe
        {
            Span<byte> md5Span = new Span<byte>(lic.md5, 16);
            hash.CopyTo(md5Span);

            Unsafe.CopyBlock(ref licenseData[0], ref Unsafe.As<License, byte>(ref lic), (uint)sizeof(License));
            licenseData.Reverse();
        }

        licenseLines.Add(string.Empty);

        BigInteger mod = new BigInteger(mod_rsa_patched, true, false);
        BigInteger pri = new BigInteger(pri_rsa, true, true);
        BigInteger msg = new BigInteger(licenseData, true, false);
        BigInteger emsg = BigInteger.ModPow(msg, pri, mod);

        ThrowHelper(emsg.TryWriteBytes(signatureData, out int bytesWritten, true, false) == false, nameof(signatureData));

        int remaining = signatureData.Length;
        for (int i = 0; i < signatureData.Length;)
        {
            int len = Math.Min(remaining, 57);
            licenseLines.Add($"S:{Convert.ToBase64String(signatureData.Slice(i, len))}");
            i += len;
            remaining -= len;
        }

        licenseLines.Add(string.Empty);

        return (lic, licenseLines);
    }

    // original ida modulus
    static ReadOnlySpan<byte> mod_rsa => new byte[]
    {
        0xED, 0xFD, 0x42, 0x5C, 0xF9, 0x78, 0x54, 0x6E, 0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6C, 0x57,
        0x14, 0x05, 0x25, 0x65, 0x0B, 0xCF, 0x6E, 0xBF, 0xE8, 0x0E, 0xDB, 0xC5, 0xFB, 0x1D, 0xE6, 0x8F,
        0x4C, 0x66, 0xC2, 0x9C, 0xB2, 0x2E, 0xB6, 0x68, 0x78, 0x8A, 0xFC, 0xB0, 0xAB, 0xBB, 0x71, 0x80,
        0x44, 0x58, 0x4B, 0x81, 0x0F, 0x89, 0x70, 0xCD, 0xDF, 0x22, 0x73, 0x85, 0xF7, 0x5D, 0x5D, 0xDD,
        0xD9, 0x1D, 0x4F, 0x18, 0x93, 0x7A, 0x08, 0xAA, 0x83, 0xB2, 0x8C, 0x49, 0xD1, 0x2D, 0xC9, 0x2E,
        0x75, 0x05, 0xBB, 0x38, 0x80, 0x9E, 0x91, 0xBD, 0x0F, 0xBD, 0x2F, 0x2E, 0x6A, 0xB1, 0xD2, 0xE3,
        0x3C, 0x0C, 0x55, 0xD5, 0xBD, 0xDD, 0x47, 0x8E, 0xE8, 0xBF, 0x84, 0x5F, 0xCE, 0xF3, 0xC8, 0x2B,
        0x9D, 0x29, 0x29, 0xEC, 0xB7, 0x1F, 0x4D, 0x1B, 0x3D, 0xB9, 0x6E, 0x3A, 0x8E, 0x7A, 0xAF, 0x93
    };

    // patched modulus, same patch must be applied to ida.dll/ida64.dll for generated keys to work
    static ReadOnlySpan<byte> mod_rsa_patched => new byte[]
    {
        0xED, 0xFD, 0x42, 0xCB, 0xF9, 0x78, 0x54, 0x6E, 0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6C, 0x57,
        0x14, 0x05, 0x25, 0x65, 0x0B, 0xCF, 0x6E, 0xBF, 0xE8, 0x0E, 0xDB, 0xC5, 0xFB, 0x1D, 0xE6, 0x8F,
        0x4C, 0x66, 0xC2, 0x9C, 0xB2, 0x2E, 0xB6, 0x68, 0x78, 0x8A, 0xFC, 0xB0, 0xAB, 0xBB, 0x71, 0x80,
        0x44, 0x58, 0x4B, 0x81, 0x0F, 0x89, 0x70, 0xCD, 0xDF, 0x22, 0x73, 0x85, 0xF7, 0x5D, 0x5D, 0xDD,
        0xD9, 0x1D, 0x4F, 0x18, 0x93, 0x7A, 0x08, 0xAA, 0x83, 0xB2, 0x8C, 0x49, 0xD1, 0x2D, 0xC9, 0x2E,
        0x75, 0x05, 0xBB, 0x38, 0x80, 0x9E, 0x91, 0xBD, 0x0F, 0xBD, 0x2F, 0x2E, 0x6A, 0xB1, 0xD2, 0xE3,
        0x3C, 0x0C, 0x55, 0xD5, 0xBD, 0xDD, 0x47, 0x8E, 0xE8, 0xBF, 0x84, 0x5F, 0xCE, 0xF3, 0xC8, 0x2B,
        0x9D, 0x29, 0x29, 0xEC, 0xB7, 0x1F, 0x4D, 0x1B, 0x3D, 0xB9, 0x6E, 0x3A, 0x8E, 0x7A, 0xAF, 0x93
    };

    // private key for patched modulus
    static ReadOnlySpan<byte> pri_rsa => new byte[]
    {
        0x74, 0x98, 0x02, 0x70, 0x49, 0x14, 0x0B, 0x81, 0x15, 0x8D, 0xBA, 0xB9, 0x9F, 0x7E, 0xD0, 0x02,
        0xD1, 0xB9, 0x98, 0x0E, 0xB7, 0x32, 0xE8, 0x59, 0x47, 0xE7, 0xE4, 0xF4, 0x2F, 0x28, 0x32, 0x15,
        0x1F, 0xA6, 0x56, 0x2B, 0x67, 0xD4, 0xD8, 0xA0, 0xA3, 0x22, 0x1E, 0xD1, 0x04, 0x5D, 0xC0, 0xF0,
        0xB9, 0x25, 0x8F, 0xF6, 0x11, 0xA4, 0xF8, 0xB8, 0xC9, 0x9A, 0xE7, 0x81, 0x99, 0xED, 0x9E, 0x4D,
        0xAE, 0xC2, 0xF9, 0x57, 0x9F, 0x3F, 0xF3, 0x1C, 0x79, 0xC4, 0xA2, 0x19, 0xB6, 0xEA, 0xA4, 0x00,
        0x2F, 0x82, 0x35, 0xD8, 0x63, 0x4E, 0x1C, 0x7A, 0x01, 0xD3, 0x32, 0x57, 0x1D, 0x71, 0x0D, 0x64,
        0xDD, 0x64, 0xD4, 0x4D, 0x81, 0x41, 0x26, 0xB7, 0xBF, 0x8D, 0x60, 0x16, 0x78, 0x45, 0xA5, 0xB1,
        0xBE, 0x47, 0xFF, 0x68, 0x7B, 0x79, 0x36, 0x44, 0x13, 0xBB, 0xF3, 0xB7, 0xBB, 0x6A, 0xC8, 0x77
    };

    static ReadOnlySpan<byte> exp_rsa => new byte[] { 0x13 };
}

class MD5
{
    private readonly System.Security.Cryptography.MD5 md5;

    public MD5() => md5 = System.Security.Cryptography.MD5.Create();

    public void Init() => md5.Initialize();

    public void Update(string str) => Update(Encoding.UTF8.GetBytes(str));

    public void Update(byte[] data) => md5.TransformBlock(data, 0, data.Length, data, 0);

    public byte[] Final()
    {
        byte[] buf = Array.Empty<byte>();
        md5.TransformFinalBlock(buf, 0, buf.Length);
        return md5.Hash!;
    }
}
