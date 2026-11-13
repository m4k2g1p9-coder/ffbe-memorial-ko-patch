// APK overlay patcher: no Java / Android SDK needed. C# 5 (Windows PowerShell Add-Type).
// Reads the user's APK, replaces/appends/adds files from a payload folder, re-aligns, and signs with APK Signature Scheme v2.
//   payload\replace\<apk path>  -> file replaces that entry (deflate)
//   payload\append\<apk path>   -> file bytes are appended to that entry (original is inflated first)
//   payloaddd\<apk path>      -> new file added (deflated)
//   payload\stored\<apk path>   -> file added/replaced, stored without compression (readable in place by the hook)
//   payload\delta\<apk path>    -> KD1 delta: the entry is rebuilt from an entry already in the APK
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class ApkPatcher
{
    class Entry
    {
        public byte[] Name; public string Str;
        public ushort VerMade, VerNeed, Flags, Method, Time, Date, Disk, IAttr;
        public uint Crc, CSize, USize, EAttr, Lho;
        public byte[] CExtra, Comment;
    }

    static uint[] crcTable;
    static uint Crc32(byte[] d)
    {
        if (crcTable == null)
        {
            crcTable = new uint[256];
            for (uint i = 0; i < 256; i++) { uint c = i; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1; crcTable[i] = c; }
        }
        uint r = 0xFFFFFFFFu;
        for (int i = 0; i < d.Length; i++) r = crcTable[(r ^ d[i]) & 0xFF] ^ (r >> 8);
        return ~r;
    }

    public static string Sha256File(string path)
    {
        using (var f = File.OpenRead(path)) using (var h = SHA256.Create())
            return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
    }

    static byte[] ReadExact(Stream s, long off, int len)
    {
        var b = new byte[len]; s.Position = off; int n = 0;
        while (n < len) { int r = s.Read(b, n, len - n); if (r <= 0) throw new IOException("unexpected end of file"); n += r; }
        return b;
    }
    static ushort U16(byte[] b, int o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
    static uint U32(byte[] b, int o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

    static List<Entry> ReadCentral(FileStream f, out long cdOff, out long eocdOff)
    {
        long len = f.Length; int tl = (int)Math.Min(len, 65557);
        var tail = ReadExact(f, len - tl, tl); int e = -1;
        for (int i = tl - 22; i >= 0; i--) if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 5 && tail[i + 3] == 6) { e = i; break; }
        if (e < 0) throw new InvalidDataException("not a ZIP/APK (no end record)");
        eocdOff = len - tl + e;
        int count = U16(tail, e + 10); uint cdSize = U32(tail, e + 12); cdOff = U32(tail, e + 16);
        if (count == 0xFFFF || cdOff == 0xFFFFFFFFu) throw new NotSupportedException("ZIP64 is not supported");
        var cd = ReadExact(f, cdOff, (int)cdSize);
        var list = new List<Entry>(); int p = 0;
        for (int k = 0; k < count; k++)
        {
            if (U32(cd, p) != 0x02014b50) throw new InvalidDataException("bad central directory");
            var en = new Entry();
            en.VerMade = U16(cd, p + 4); en.VerNeed = U16(cd, p + 6); en.Flags = U16(cd, p + 8); en.Method = U16(cd, p + 10);
            en.Time = U16(cd, p + 12); en.Date = U16(cd, p + 14); en.Crc = U32(cd, p + 16); en.CSize = U32(cd, p + 20); en.USize = U32(cd, p + 24);
            int n = U16(cd, p + 28), m = U16(cd, p + 30), c = U16(cd, p + 32);
            en.Disk = U16(cd, p + 34); en.IAttr = U16(cd, p + 36); en.EAttr = U32(cd, p + 38); en.Lho = U32(cd, p + 42);
            en.Name = new byte[n]; Array.Copy(cd, p + 46, en.Name, 0, n); en.Str = Encoding.UTF8.GetString(en.Name);
            en.CExtra = new byte[m]; Array.Copy(cd, p + 46 + n, en.CExtra, 0, m);
            en.Comment = new byte[c]; Array.Copy(cd, p + 46 + n + m, en.Comment, 0, c);
            list.Add(en); p += 46 + n + m + c;
        }
        return list;
    }

    static byte[] ReadEntryData(FileStream f, Entry e) // inflated bytes
    {
        var h = ReadExact(f, e.Lho, 30); long pos = e.Lho + 30 + U16(h, 26) + U16(h, 28);
        var raw = ReadExact(f, pos, (int)e.CSize);
        if (e.Method == 0) return raw;
        using (var ms = new MemoryStream(raw)) using (var ds = new DeflateStream(ms, CompressionMode.Decompress)) using (var o = new MemoryStream())
        { ds.CopyTo(o); return o.ToArray(); }
    }

    static byte[] Deflate(byte[] d)
    {
        using (var o = new MemoryStream())
        {
            using (var ds = new DeflateStream(o, CompressionLevel.Optimal, true)) ds.Write(d, 0, d.Length);
            return o.ToArray();
        }
    }

    static void W16(Stream s, int v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    static void W32(Stream s, uint v) { W16(s, (int)(v & 0xFFFF)); W16(s, (int)(v >> 16)); }
    static void W64(Stream s, long v) { W32(s, (uint)(v & 0xFFFFFFFFL)); W32(s, (uint)(v >> 32)); }
    static void WB(Stream s, byte[] b) { s.Write(b, 0, b.Length); }

    static byte[] AlignPad(long baseOff, int align)
    {
        int pad = (int)((align - baseOff % align) % align);
        if (pad == 0) return new byte[0];
        while (pad < 6) pad += align;
        var x = new byte[pad]; x[0] = 0x35; x[1] = 0xD9; x[2] = (byte)(pad - 4); x[3] = (byte)((pad - 4) >> 8); x[4] = (byte)align; x[5] = (byte)(align >> 8);
        return x;
    }

    static void CopyRange(Stream src, long start, long end, Stream dst)
    {
        var buf = new byte[1 << 20]; src.Position = start; long left = end - start;
        while (left > 0) { int r = src.Read(buf, 0, (int)Math.Min(buf.Length, left)); if (r <= 0) throw new IOException("short read"); dst.Write(buf, 0, r); left -= r; }
    }

    static string Norm(string p) { return p.Replace('\\', '/'); }

    static Dictionary<string, string> Scan(string dir)
    {
        var d = new Dictionary<string, string>();
        if (!Directory.Exists(dir)) return d;
        string root = Path.GetFullPath(dir).TrimEnd('\\', '/') + "\\";
        foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories)) d[Norm(Path.GetFullPath(f).Substring(root.Length))] = f;
        return d;
    }

    // ---------- signing key ----------
    static void LoadOrCreateKey(string keyDir, out RSACryptoServiceProvider rsa, out byte[] certDer)
    {
        Directory.CreateDirectory(keyDir);
        string kf = Path.Combine(keyDir, "signing_key.txt"), cf = Path.Combine(keyDir, "signing_cert.der");
        rsa = new RSACryptoServiceProvider();
        if (File.Exists(kf) && File.Exists(cf))
        {
            var L = File.ReadAllLines(kf); var p = new RSAParameters();
            p.Modulus = Convert.FromBase64String(L[0]); p.Exponent = Convert.FromBase64String(L[1]); p.D = Convert.FromBase64String(L[2]);
            p.P = Convert.FromBase64String(L[3]); p.Q = Convert.FromBase64String(L[4]); p.DP = Convert.FromBase64String(L[5]);
            p.DQ = Convert.FromBase64String(L[6]); p.InverseQ = Convert.FromBase64String(L[7]);
            rsa.ImportParameters(p); certDer = File.ReadAllBytes(cf);
            Console.WriteLine("  signing key: reused (" + keyDir + ")");
            return;
        }
        rsa = new RSACryptoServiceProvider(2048);
        var req = new CertificateRequest("CN=FFBE KO Patch, O=Local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(30));
        certDer = cert.RawData;
        var q = rsa.ExportParameters(true);
        File.WriteAllLines(kf, new string[] { Convert.ToBase64String(q.Modulus), Convert.ToBase64String(q.Exponent), Convert.ToBase64String(q.D),
            Convert.ToBase64String(q.P), Convert.ToBase64String(q.Q), Convert.ToBase64String(q.DP), Convert.ToBase64String(q.DQ), Convert.ToBase64String(q.InverseQ) });
        File.WriteAllBytes(cf, certDer);
        Console.WriteLine("  signing key: created (" + keyDir + ") - keep this folder to update later without reinstalling");
    }

    static byte[] DerLen(int n)
    {
        if (n < 128) return new byte[] { (byte)n };
        if (n < 256) return new byte[] { 0x81, (byte)n };
        return new byte[] { 0x82, (byte)(n >> 8), (byte)n };
    }
    static byte[] Der(byte tag, byte[] body)
    {
        var l = DerLen(body.Length); var r = new byte[1 + l.Length + body.Length];
        r[0] = tag; Array.Copy(l, 0, r, 1, l.Length); Array.Copy(body, 0, r, 1 + l.Length, body.Length); return r;
    }
    static byte[] Cat(params byte[][] parts)
    {
        using (var m = new MemoryStream()) { foreach (var p in parts) m.Write(p, 0, p.Length); return m.ToArray(); }
    }
    static byte[] Spki(X509Certificate2 cert)
    {
        var algId = new byte[] { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
        var bits = Der(0x03, Cat(new byte[] { 0 }, cert.GetPublicKey()));
        return Der(0x30, Cat(algId, bits));
    }

    static byte[] LP(byte[] b) // uint32 length prefix
    {
        var r = new byte[4 + b.Length]; r[0] = (byte)b.Length; r[1] = (byte)(b.Length >> 8); r[2] = (byte)(b.Length >> 16); r[3] = (byte)(b.Length >> 24);
        Array.Copy(b, 0, r, 4, b.Length); return r;
    }
    static byte[] LE32(uint v) { return new byte[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) }; }

    static void ChunkDigests(Stream f, long start, long end, List<byte[]> outList)
    {
        using (var sha = SHA256.Create())
        {
            long p = start;
            while (p < end)
            {
                int n = (int)Math.Min(1 << 20, end - p); var data = ReadExact(f, p, n);
                var pre = Cat(new byte[] { 0xA5 }, LE32((uint)n), data);
                outList.Add(sha.ComputeHash(pre)); p += n;
            }
        }
    }

    // ---------- main ----------
    public static void Run(string inApk, string outApk, string payloadDir, string keyDir)
    {
        var replace = Scan(Path.Combine(payloadDir, "replace"));
        var append = Scan(Path.Combine(payloadDir, "append"));
        var stored = Scan(Path.Combine(payloadDir, "stored"));
        var add = Scan(Path.Combine(payloadDir, "add"));
        var delta = Scan(Path.Combine(payloadDir, "delta"));
        string tmp = outApk + ".unsigned.tmp";
        long cdOff, eocdOff;
        using (var f = File.OpenRead(inApk))
        {
            var entries = ReadCentral(f, out cdOff, out eocdOff);
            var names = new HashSet<string>();
            var byName = new Dictionary<string, Entry>();
            foreach (var e in entries) { names.Add(e.Str); byName[e.Str] = e; }
            foreach (var k in append.Keys) if (!names.Contains(k)) throw new InvalidDataException("append target not in APK: " + k);
            foreach (var k in replace.Keys) if (!names.Contains(k)) throw new InvalidDataException("replace target not in APK: " + k);
            var outList = new List<Entry>();
            using (var o = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            {
                foreach (var e in entries)
                {
                    string n = e.Str;
                    if (n == "META-INF/MANIFEST.MF" || (n.StartsWith("META-INF/") && (n.EndsWith(".SF") || n.EndsWith(".RSA") || n.EndsWith(".DSA") || n.EndsWith(".EC")))) continue;
                    byte[] data = null; bool store = false; string src;
                    if (stored.TryGetValue(n, out src)) { data = File.ReadAllBytes(src); store = true; }
                    else if (replace.TryGetValue(n, out src)) { data = File.ReadAllBytes(src); }
                    else if (append.TryGetValue(n, out src)) { data = Cat(ReadEntryData(f, e), File.ReadAllBytes(src)); }
                    else if (delta.TryGetValue(n, out src)) { data = ApplyDelta(f, byName, File.ReadAllBytes(src), out store); }
                    WriteEntry(o, f, e, data, store, outList);
                }
                var newFiles = new List<KeyValuePair<string, string>>();
                foreach (var kv in stored) newFiles.Add(kv);
                foreach (var kv in add) { if (!names.Contains(kv.Key)) newFiles.Add(kv); }
                foreach (var kv in delta) newFiles.Add(kv);
                foreach (var kv in newFiles)
                {
                    if (names.Contains(kv.Key)) continue;
                    bool st = stored.ContainsKey(kv.Key);
                    var ne = new Entry(); ne.Name = Encoding.UTF8.GetBytes(kv.Key); ne.Str = kv.Key; ne.VerMade = 20; ne.VerNeed = 20; ne.Flags = 0x0800;
                    var now = DateTime.Now; ne.Time = (ushort)((now.Hour << 11) | (now.Minute << 5) | (now.Second / 2)); ne.Date = (ushort)(((now.Year - 1980) << 9) | (now.Month << 5) | now.Day);
                    ne.CExtra = new byte[0]; ne.Comment = new byte[0];
                    byte[] nd = File.ReadAllBytes(kv.Value);
                    if (delta.ContainsKey(kv.Key)) nd = ApplyDelta(f, byName, nd, out st);
                    WriteEntry(o, null, ne, nd, st, outList);
                }
                long newCd = o.Position;
                foreach (var e in outList)
                {
                    W32(o, 0x02014b50); W16(o, e.VerMade); W16(o, e.VerNeed); W16(o, e.Flags); W16(o, e.Method); W16(o, e.Time); W16(o, e.Date);
                    W32(o, e.Crc); W32(o, e.CSize); W32(o, e.USize); W16(o, e.Name.Length); W16(o, e.CExtra.Length); W16(o, e.Comment.Length);
                    W16(o, 0); W16(o, e.IAttr); W32(o, e.EAttr); W32(o, e.Lho); WB(o, e.Name); WB(o, e.CExtra); WB(o, e.Comment);
                }
                long cdSize = o.Position - newCd;
                W32(o, 0x06054b50); W16(o, 0); W16(o, 0); W16(o, outList.Count); W16(o, outList.Count); W32(o, (uint)cdSize); W32(o, (uint)newCd); W16(o, 0);
            }
        }
        Console.WriteLine("  entries written, signing...");
        Sign(tmp, outApk, keyDir);
        File.Delete(tmp);
    }

    // KD1 delta (see kdelta.py): rebuilds a file from an entry of the user's own APK; inserted bytes are XORed with that entry
    static string deltaBaseName; static byte[] deltaBase;
    static byte[] ApplyDelta(FileStream f, Dictionary<string, Entry> byName, byte[] d, out bool store)
    {
        if (d.Length < 39 || d[0] != 'K' || d[1] != 'D' || d[2] != '1' || d[3] != 0) throw new InvalidDataException("bad delta file");
        store = d[4] != 0; int n = U16(d, 5); string baseName = Encoding.UTF8.GetString(d, 7, n); int p = 7 + n + 32;
        if (baseName != deltaBaseName)
        {
            Entry be; if (!byName.TryGetValue(baseName, out be)) throw new InvalidDataException("delta base not in APK: " + baseName);
            deltaBase = ReadEntryData(f, be); deltaBaseName = baseName;
        }
        byte[] b = deltaBase;
        using (var ms = new MemoryStream())
        {
            while (p < d.Length)
            {
                long co = U32(d, p), cl = U32(d, p + 4), il = U32(d, p + 8), xo = U32(d, p + 12); p += 16;
                if (co + cl > b.Length || p + il > d.Length || (il > 0 && b.Length == 0)) throw new InvalidDataException("delta base mismatch: " + baseName);
                ms.Write(b, (int)co, (int)cl);
                long k = xo % Math.Max(1, b.Length);
                for (long i = 0; i < il; i++) { ms.WriteByte((byte)(d[p + i] ^ b[k])); if (++k == b.Length) k = 0; }
                p += (int)il;
            }
            byte[] r = ms.ToArray();
            using (var sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(r);
                for (int i = 0; i < 32; i++) if (h[i] != d[7 + n + i]) throw new InvalidDataException("delta base mismatch: " + baseName + " (원본 v208 APK가 아닙니다)");
            }
            return r;
        }
    }

    static void WriteEntry(Stream o, FileStream src, Entry e, byte[] data, bool store, List<Entry> outList)
    {
        var ne = new Entry();
        ne.Name = e.Name; ne.Str = e.Str; ne.VerMade = e.VerMade; ne.VerNeed = 20; ne.Flags = (ushort)(e.Flags & ~8); ne.Time = e.Time; ne.Date = e.Date;
        ne.IAttr = e.IAttr; ne.EAttr = e.EAttr; ne.CExtra = e.CExtra; ne.Comment = e.Comment;
        byte[] payload; long rawOff = 0;
        if (data != null)
        {
            ne.Crc = Crc32(data); ne.USize = (uint)data.Length;
            if (store) { ne.Method = 0; payload = data; } else { ne.Method = 8; payload = Deflate(data); }
            ne.CSize = (uint)payload.Length;
        }
        else
        {
            ne.Method = e.Method; ne.Crc = e.Crc; ne.CSize = e.CSize; ne.USize = e.USize; payload = null;
            var h = ReadExact(src, e.Lho, 30); rawOff = e.Lho + 30 + U16(h, 26) + U16(h, 28);
        }
        ne.Lho = (uint)o.Position;
        byte[] extra = new byte[0];
        if (ne.Method == 0) extra = AlignPad(ne.Lho + 30 + ne.Name.Length, ne.Str.EndsWith(".so") ? 4096 : 4);
        W32(o, 0x04034b50); W16(o, ne.VerNeed); W16(o, ne.Flags); W16(o, ne.Method); W16(o, ne.Time); W16(o, ne.Date);
        W32(o, ne.Crc); W32(o, ne.CSize); W32(o, ne.USize); W16(o, ne.Name.Length); W16(o, extra.Length); WB(o, ne.Name); WB(o, extra);
        if (payload != null) WB(o, payload); else CopyRange(src, rawOff, rawOff + ne.CSize, o);
        outList.Add(ne);
    }

    static void Sign(string unsignedPath, string outPath, string keyDir)
    {
        RSACryptoServiceProvider rsa; byte[] certDer;
        LoadOrCreateKey(keyDir, out rsa, out certDer);
        var cert = new X509Certificate2(certDer);
        long cdOff, eocdOff; List<byte[]> digs = new List<byte[]>();
        using (var f = File.OpenRead(unsignedPath))
        {
            ReadCentral(f, out cdOff, out eocdOff);
            ChunkDigests(f, 0, cdOff, digs); ChunkDigests(f, cdOff, eocdOff, digs); ChunkDigests(f, eocdOff, f.Length, digs);
        }
        byte[] top;
        using (var sha = SHA256.Create())
        {
            var all = new List<byte[]>(); all.Add(new byte[] { 0x5A }); all.Add(LE32((uint)digs.Count)); all.AddRange(digs);
            top = sha.ComputeHash(Cat(all.ToArray()));
        }
        var digestEntry = LP(Cat(LE32(0x0103), LP(top)));
        var signedData = Cat(LP(digestEntry), LP(LP(certDer)), LP(new byte[0]));
        var sig = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signer = Cat(LP(signedData), LP(LP(Cat(LE32(0x0103), LP(sig)))), LP(Spki(cert)));
        var value = LP(LP(signer));
        long pairLen = 4 + value.Length;
        long blockSize = 8 + pairLen + 8 + 16;
        using (var ms = new MemoryStream())
        {
            W64(ms, blockSize); W64(ms, pairLen); W32(ms, 0x7109871A); WB(ms, value); W64(ms, blockSize); WB(ms, Encoding.ASCII.GetBytes("APK Sig Block 42"));
            var block = ms.ToArray();
            using (var f = File.OpenRead(unsignedPath)) using (var o = new FileStream(outPath, FileMode.Create, FileAccess.Write))
            {
                CopyRange(f, 0, cdOff, o); WB(o, block); CopyRange(f, cdOff, eocdOff, o);
                var eocd = ReadExact(f, eocdOff, (int)(f.Length - eocdOff));
                uint newOff = (uint)(cdOff + block.Length); eocd[16] = (byte)newOff; eocd[17] = (byte)(newOff >> 8); eocd[18] = (byte)(newOff >> 16); eocd[19] = (byte)(newOff >> 24);
                WB(o, eocd);
            }
        }
    }
}
