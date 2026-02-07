using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var dataDir = Environment.GetEnvironmentVariable("DATA_DIR") ?? AppContext.BaseDirectory;
var uploadsDir = Path.Combine(dataDir, "uploads");
Directory.CreateDirectory(uploadsDir);

// Ukládání do DB (SQLite)
var dbFile = Path.Combine(dataDir, "treninky.db");
var cs = new SqliteConnectionStringBuilder
{
DataSource = dbFile,
Mode = SqliteOpenMode.ReadWriteCreate,
Cache = SqliteCacheMode.Shared,
DefaultTimeout = 5 // seconds (busy timeout)
}.ToString();

void InitDb()
{
using var conn = new SqliteConnection(cs);
conn.Open();

// Lepší souběh čtení/zápisu pro web aplikaci
using (var prag = conn.CreateCommand())
{
prag.CommandText = "PRAGMA journal_mode=WAL;";
prag.ExecuteNonQuery();
prag.CommandText = "PRAGMA synchronous=NORMAL;";
prag.ExecuteNonQuery();
prag.CommandText = "PRAGMA busy_timeout=5000;";
prag.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS treninky (
id INTEGER PRIMARY KEY AUTOINCREMENT,
datum TEXT NOT NULL,
typ TEXT NOT NULL,

poznamka TEXT,
tagy TEXT,
pocasi TEXT,
user_id INTEGER,
is_public INTEGER NOT NULL DEFAULT 0,

cviceni TEXT,
serie INTEGER,
opakovani INTEGER,
dobaMinuty INTEGER,

vzdalenostKm REAL,
tempo TEXT,
prevyseniM INTEGER,
tep INTEGER,

velikostBazenuM INTEGER,
vzdalenostM INTEGER,
dobaPlavaniMin INTEGER
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
is_admin INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS sessions (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
token TEXT NOT NULL UNIQUE,
expires_at INTEGER NOT NULL
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS trenink_fotky (
id INTEGER PRIMARY KEY AUTOINCREMENT,
trenink_id INTEGER NOT NULL,
user_id INTEGER,
file_name TEXT NOT NULL,
original_name TEXT,
content_type TEXT,
created_at TEXT NOT NULL
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS custom_types (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
key TEXT NOT NULL,
name TEXT NOT NULL,
created_at TEXT NOT NULL
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS custom_fields (
id INTEGER PRIMARY KEY AUTOINCREMENT,
type_id INTEGER NOT NULL,
key TEXT NOT NULL,
label TEXT NOT NULL,
data_type TEXT NOT NULL,
unit TEXT,
min_value REAL,
max_value REAL,
sort_order INTEGER NOT NULL DEFAULT 0
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE TABLE IF NOT EXISTS custom_values (
id INTEGER PRIMARY KEY AUTOINCREMENT,
trenink_id INTEGER NOT NULL,
field_id INTEGER NOT NULL,
value TEXT
);
""";
cmd.ExecuteNonQuery();
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_types_user_key ON custom_types(user_id, key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_fields_type_key ON custom_fields(type_id, key);
CREATE INDEX IF NOT EXISTS idx_custom_values_trenink ON custom_values(trenink_id);
CREATE INDEX IF NOT EXISTS idx_custom_values_field ON custom_values(field_id);
""";
cmd.ExecuteNonQuery();
}

// Jednoduchá migrace: přidat sloupce do existující DB
var hasPoznamka = false;
var hasTagy = false;
var hasPocasi = false;
var hasUserId = false;
var hasIsAdmin = false;
var hasIsPublic = false;
using (var cmdInfo = conn.CreateCommand())
{
cmdInfo.CommandText = "PRAGMA table_info(treninky);";
using var r = cmdInfo.ExecuteReader();
while (r.Read())
{
if (!r.IsDBNull(1))
{
var name = r.GetString(1);
if (string.Equals(name, "poznamka", StringComparison.OrdinalIgnoreCase)) hasPoznamka = true;
if (string.Equals(name, "tagy", StringComparison.OrdinalIgnoreCase)) hasTagy = true;
if (string.Equals(name, "pocasi", StringComparison.OrdinalIgnoreCase)) hasPocasi = true;
if (string.Equals(name, "user_id", StringComparison.OrdinalIgnoreCase)) hasUserId = true;
if (string.Equals(name, "is_public", StringComparison.OrdinalIgnoreCase)) hasIsPublic = true;
}
}
}

if (!hasPoznamka)
{
using var cmdAlter = conn.CreateCommand();
cmdAlter.CommandText = "ALTER TABLE treninky ADD COLUMN poznamka TEXT;";
cmdAlter.ExecuteNonQuery();
}

if (!hasTagy)
{
using var cmdAlter2 = conn.CreateCommand();
cmdAlter2.CommandText = "ALTER TABLE treninky ADD COLUMN tagy TEXT;";
cmdAlter2.ExecuteNonQuery();
}

if (!hasPocasi)
{
using var cmdAlter3 = conn.CreateCommand();
cmdAlter3.CommandText = "ALTER TABLE treninky ADD COLUMN pocasi TEXT;";
cmdAlter3.ExecuteNonQuery();
}

if (!hasUserId)
{
using var cmdAlter4 = conn.CreateCommand();
cmdAlter4.CommandText = "ALTER TABLE treninky ADD COLUMN user_id INTEGER;";
cmdAlter4.ExecuteNonQuery();
}

if (!hasIsPublic)
{
using var cmdAlter5 = conn.CreateCommand();
cmdAlter5.CommandText = "ALTER TABLE treninky ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0;";
cmdAlter5.ExecuteNonQuery();
}

using (var cmdInfo = conn.CreateCommand())
{
cmdInfo.CommandText = "PRAGMA table_info(users);";
using var r = cmdInfo.ExecuteReader();
while (r.Read())
{
if (!r.IsDBNull(1))
{
var name = r.GetString(1);
if (string.Equals(name, "is_admin", StringComparison.OrdinalIgnoreCase)) hasIsAdmin = true;
}
}
}

if (!hasIsAdmin)
{
using var cmdAlterUsers = conn.CreateCommand();
cmdAlterUsers.CommandText = "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;";
cmdAlterUsers.ExecuteNonQuery();
}
}

string DateToIso(DateTime dt) => dt.Date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
DateTime IsoToDate(string s)
{
if (DateTime.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
return dt.Date;
if (DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
return dt.Date;
return DateTime.Today;
}

var BuiltInTypes = new (string Key, string Label)[]
{
("beh", "Běh"),
("kolo", "Kolo"),
("turistika", "Turistika"),
("cviceni", "Cvičení"),
("plavani", "Plavání")
};

bool IsBuiltInType(string? key)
{
if (string.IsNullOrWhiteSpace(key)) return false;
return BuiltInTypes.Any(t => string.Equals(t.Key, key.Trim(), StringComparison.OrdinalIgnoreCase));
}

string NormalizeKey(string input)
{
var sb = new StringBuilder();
foreach (var ch in input.Trim().ToLowerInvariant())
{
if (char.IsLetterOrDigit(ch)) sb.Append(ch);
else if (ch == ' ' || ch == '-' || ch == '_') sb.Append('_');
}
var key = sb.ToString().Trim('_');
return string.IsNullOrWhiteSpace(key) ? "typ" : key;
}

double ClampDouble(double value, double? min, double? max)
{
if (min is not null && value < min.Value) return min.Value;
if (max is not null && value > max.Value) return max.Value;
return value;
}

string? NormalizeUnit(string? unit)
{
var u = (unit ?? "").Trim();
return string.IsNullOrWhiteSpace(u) ? null : u;
}

string GetTypeLabel(TreninkovyZaznam z, Dictionary<string, string> userMap, Dictionary<(int, string), string> allMap)
{
foreach (var t in BuiltInTypes)
{
if (string.Equals(z.Typ, t.Key, StringComparison.OrdinalIgnoreCase)) return t.Label;
}
if (userMap.TryGetValue(z.Typ, out var name)) return name;
if (allMap.TryGetValue((z.UserId, z.Typ), out var name2)) return name2;
return z.Typ;
}

bool TryParseCustomHeader(string header, out string typeKey, out string fieldKey)
{
typeKey = "";
fieldKey = "";
if (string.IsNullOrWhiteSpace(header)) return false;
var h = header.Trim();
if (!h.StartsWith("custom_", StringComparison.OrdinalIgnoreCase)) return false;
var rest = h.Substring("custom_".Length);
var idx = rest.IndexOf('_');
if (idx <= 0 || idx >= rest.Length - 1) return false;
typeKey = rest.Substring(0, idx).Trim();
fieldKey = rest.Substring(idx + 1).Trim();
return !string.IsNullOrWhiteSpace(typeKey) && !string.IsNullOrWhiteSpace(fieldKey);
}

void WithBusyRetry(Action action)
{
// SQLite může občas vrátit "database is locked" při souběhu (např. dva požadavky rychle po sobě).
// Zkusíme krátce počkat a opakovat.
var delayMs = 50;
for (var i = 0; i < 6; i++)
{
try
{
action();
return;
}
catch (SqliteException ex) when (ex.SqliteErrorCode == 5 || ex.SqliteErrorCode == 6)
{
Thread.Sleep(delayMs);
delayMs *= 2;
}
}

// poslední pokus - ať se chyba neztratí
action();
}

async Task SavePhotosAsync(IFormFileCollection files, int treninkId, int userId)
{
if (files is null || files.Count == 0) return;

foreach (var file in files)
{
if (file.Length <= 0) continue;

var ext = Path.GetExtension(file.FileName);
if (string.IsNullOrWhiteSpace(ext) || ext.Length > 10) ext = ".jpg";
ext = ext.ToLowerInvariant();

var fileName = $"{treninkId}_{Guid.NewGuid():N}{ext}";
var path = Path.Combine(uploadsDir, fileName);

await using (var stream = File.Create(path))
{
await file.CopyToAsync(stream);
}

var contentType = string.IsNullOrWhiteSpace(file.ContentType) ? "application/octet-stream" : file.ContentType;
DbInsertPhoto(treninkId, userId, fileName, file.FileName, contentType);
}
}

const string AuthCookieName = "trenink_auth";
const int SessionDays = 30;

static string HashPassword(string password)
{
var salt = RandomNumberGenerator.GetBytes(16);
using var pbkdf2 = 
        new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
var hash = pbkdf2.GetBytes(32);
return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
}

static bool VerifyPassword(string password, string stored)
{
var parts = stored.Split(':');
if (parts.Length != 2) return false;
var salt = Convert.FromBase64String(parts[0]);
var expected = Convert.FromBase64String(parts[1]);
using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
var actual = pbkdf2.GetBytes(32);
return CryptographicOperations.FixedTimeEquals(actual, expected);
}

int DbUsersCount()
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT COUNT(1) FROM users";
return Convert.ToInt32(cmd.ExecuteScalar());
}

User? DbGetUserByUsername(string username)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT id, username, is_admin FROM users WHERE username = $u LIMIT 1;";
cmd.Parameters.AddWithValue("$u", username);
using var r = cmd.ExecuteReader();
if (!r.Read()) return null;
return new User { Id = r.GetInt32(0), Username = r.GetString(1), IsAdmin = r.GetInt32(2) == 1 };
}

User? DbGetUserById(int id)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT id, username, is_admin FROM users WHERE id = $id LIMIT 1;";
cmd.Parameters.AddWithValue("$id", id);
using var r = cmd.ExecuteReader();
if (!r.Read()) return null;
return new User { Id = r.GetInt32(0), Username = r.GetString(1), IsAdmin = r.GetInt32(2) == 1 };
}

(User? user, string? passwordHash) DbGetUserWithHash(string username)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT id, username, password_hash, is_admin FROM users WHERE username = $u LIMIT 1;";
cmd.Parameters.AddWithValue("$u", username);
using var r = cmd.ExecuteReader();
if (!r.Read()) return (null, null);
var user = new User { Id = r.GetInt32(0), Username = r.GetString(1), IsAdmin = r.GetInt32(3) == 1 };
var hash = r.GetString(2);
return (user, hash);
}

int DbCreateUser(string username, string passwordHash, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO users (username, password_hash, is_admin, created_at)
VALUES ($u, $h, $a, $c);
SELECT last_insert_rowid();
""";
cmd.Parameters.AddWithValue("$u", username);
cmd.Parameters.AddWithValue("$h", passwordHash);
cmd.Parameters.AddWithValue("$a", isAdmin ? 1 : 0);
cmd.Parameters.AddWithValue("$c", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
int id = 0;
WithBusyRetry(() => { id = Convert.ToInt32(cmd.ExecuteScalar()); });
return id;
}

void DbSetAdmin(int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "UPDATE users SET is_admin = $a WHERE id = $u";
cmd.Parameters.AddWithValue("$a", isAdmin ? 1 : 0);
cmd.Parameters.AddWithValue("$u", userId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

string DbCreateSession(int userId, out long expiresAt)
{
var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
expiresAt = DateTimeOffset.UtcNow.AddDays(SessionDays).ToUnixTimeSeconds();
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO sessions (user_id, token, expires_at)
VALUES ($u, $t, $e);
""";
cmd.Parameters.AddWithValue("$u", userId);
cmd.Parameters.AddWithValue("$t", token);
cmd.Parameters.AddWithValue("$e", expiresAt);
WithBusyRetry(() => cmd.ExecuteNonQuery());
return token;
}

User? DbGetUserBySession(string token)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT u.id, u.username, u.is_admin
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token = $t AND s.expires_at > $now
LIMIT 1;
""";
cmd.Parameters.AddWithValue("$t", token);
cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
using var r = cmd.ExecuteReader();
if (!r.Read()) return null;
return new User { Id = r.GetInt32(0), Username = r.GetString(1), IsAdmin = r.GetInt32(2) == 1 };
}

List<UserInfo> DbGetAllUsers()
{
var res = new List<UserInfo>();
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT id, username, is_admin, created_at FROM users ORDER BY username COLLATE NOCASE;";
using var r = cmd.ExecuteReader();
while (r.Read())
{
var created = r.IsDBNull(3) ? "" : r.GetString(3);
res.Add(new UserInfo
{
Id = r.GetInt32(0),
Username = r.GetString(1),
IsAdmin = r.GetInt32(2) == 1,
CreatedAt = created
});
}
return res;
}

void DbDeleteSession(string token)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "DELETE FROM sessions WHERE token = $t";
cmd.Parameters.AddWithValue("$t", token);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbDeleteSessionsForUser(int userId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "DELETE FROM sessions WHERE user_id = $u";
cmd.Parameters.AddWithValue("$u", userId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbUpdateUserPassword(int userId, string passwordHash)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "UPDATE users SET password_hash = $h WHERE id = $u";
cmd.Parameters.AddWithValue("$h", passwordHash);
cmd.Parameters.AddWithValue("$u", userId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void ClaimLegacyRecords(int userId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmdCheck = conn.CreateCommand();
cmdCheck.CommandText = "SELECT COUNT(1) FROM users";
var users = Convert.ToInt32(cmdCheck.ExecuteScalar());
if (users != 1) return;

using var cmd = conn.CreateCommand();
cmd.CommandText = "UPDATE treninky SET user_id = $u WHERE user_id IS NULL";
cmd.Parameters.AddWithValue("$u", userId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

User? CurrentUser(HttpContext context)
{
if (context.Items.TryGetValue("user", out var u) && u is User user) return user;
return null;
}

ApiRecord ToApiRecord(TreninkovyZaznam z)
{
return new ApiRecord
{
Id = z.Id,
Datum = DateToIso(z.Datum),
Typ = z.Typ,
Poznamka = z.Poznamka,
Tagy = TagSet(z.Tagy).ToArray(),
Pocasi = z.Pocasi,
IsPublic = z.IsPublic,
VzdalenostKm = z.VzdalenostKm,
Tempo = z.Tempo,
PrevyseniM = z.PrevyseniM,
Tep = z.Tep,
VelikostBazenuM = z.VelikostBazenuM,
VzdalenostM = z.VzdalenostM,
DobaPlavaniMin = z.DobaPlavaniMin,
Cviceni = z.Cviceni,
Serie = z.Serie,
Opakovani = z.Opakovani,
DobaMinuty = z.DobaMinuty
};
}

TreninkovyZaznam FromApiRecord(ApiRecordInput input, int id = 0)
{
var dt = DateTime.Today;
if (!string.IsNullOrWhiteSpace(input.Datum))
dt = IsoToDate(input.Datum);

var z = new TreninkovyZaznam
{
Id = id,
Datum = dt,
Typ = string.IsNullOrWhiteSpace(input.Typ) ? "cviceni" : input.Typ,
Poznamka = input.Poznamka ?? "",
Tagy = NormalizeTags(input.Tagy ?? Array.Empty<string>()),
Pocasi = input.Pocasi ?? "",
IsPublic = input.IsPublic ?? false,
VzdalenostKm = input.VzdalenostKm ?? 0,
Tempo = input.Tempo ?? "",
PrevyseniM = input.PrevyseniM ?? 0,
Tep = input.Tep ?? 0,
VelikostBazenuM = input.VelikostBazenuM ?? 0,
VzdalenostM = input.VzdalenostM ?? 0,
DobaPlavaniMin = input.DobaPlavaniMin ?? 0,
Cviceni = input.Cviceni ?? "",
Serie = input.Serie ?? 0,
Opakovani = input.Opakovani ?? 0,
DobaMinuty = input.DobaMinuty ?? 0
};
return z;
}

void EnsureDefaultAdmin()
{
var admin = DbGetUserByUsername("admin");
if (admin is null)
{
var hash = HashPassword("admin");
DbCreateUser("admin", hash, isAdmin: true);
return;
}
if (!admin.IsAdmin)
{
DbSetAdmin(admin.Id, true);
}
}

static void SetAuthCookie(HttpContext context, string token, long expiresAt)
{
var options = new CookieOptions
{
HttpOnly = true,
SameSite = SameSiteMode.Lax,
Expires = DateTimeOffset.FromUnixTimeSeconds(expiresAt)
};
context.Response.Cookies.Append(AuthCookieName, token, options);
}

List<TreninkovyZaznam> DbGetAll(int? userId)
{
return DbQuery(userId, null, null, null, null, null);
}

List<TreninkovyZaznam> DbGetPublicLatest(int limit)
{
var res = new List<TreninkovyZaznam>();
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT id, datum, typ,
poznamka,
tagy,
pocasi,
user_id,
is_public,
cviceni, serie, opakovani, dobaMinuty,
vzdalenostKm, tempo, prevyseniM, tep,
velikostBazenuM, vzdalenostM, dobaPlavaniMin
FROM treninky
WHERE is_public = 1
ORDER BY datum DESC, id DESC
LIMIT $limit;
""";
cmd.Parameters.AddWithValue("$limit", limit);
using var r = cmd.ExecuteReader();
while (r.Read())
{
var z = new TreninkovyZaznam
{
Id = r.GetInt32(0),
Datum = IsoToDate(r.GetString(1)),
Typ = r.GetString(2)
};
z.Poznamka = r.IsDBNull(3) ? string.Empty : r.GetString(3);
z.Tagy = r.IsDBNull(4) ? string.Empty : r.GetString(4);
z.Pocasi = r.IsDBNull(5) ? string.Empty : r.GetString(5);
z.UserId = r.IsDBNull(6) ? 0 : r.GetInt32(6);
z.IsPublic = !r.IsDBNull(7) && r.GetInt32(7) == 1;

z.Cviceni = r.IsDBNull(8) ? string.Empty : r.GetString(8);
z.Serie = r.IsDBNull(9) ? 0 : r.GetInt32(9);
z.Opakovani = r.IsDBNull(10) ? 0 : r.GetInt32(10);
z.DobaMinuty = r.IsDBNull(11) ? 0 : r.GetInt32(11);

z.VzdalenostKm = r.IsDBNull(12) ? 0 : r.GetDouble(12);
z.Tempo = r.IsDBNull(13) ? string.Empty : r.GetString(13);
z.PrevyseniM = r.IsDBNull(14) ? 0 : r.GetInt32(14);
z.Tep = r.IsDBNull(15) ? 0 : r.GetInt32(15);

z.VelikostBazenuM = r.IsDBNull(16) ? 0 : r.GetInt32(16);
z.VzdalenostM = r.IsDBNull(17) ? 0 : r.GetInt32(17);
z.DobaPlavaniMin = r.IsDBNull(18) ? 0 : r.GetInt32(18);
res.Add(z);
}
return res;
}

var KnownTags = new[] { "intervaly", "závod", "easy", "bolest" };

static string NormalizeTags(IEnumerable<string> tags)
{
var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var t in tags)
{
var x = (t ?? "").Trim();
if (string.IsNullOrWhiteSpace(x)) continue;
set.Add(x.ToLowerInvariant());
}
return string.Join(',', set.OrderBy(x => x, StringComparer.Ordinal));
}

static HashSet<string> TagSet(string? csv)
{
var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
if (string.IsNullOrWhiteSpace(csv)) return set;
foreach (var p in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
set.Add(p);
return set;
}

List<TreninkovyZaznam> DbQuery(int? userId, DateTime? from, DateTime? to, string? typ, string? q, List<string>? tags)
{
var res = new List<TreninkovyZaznam>();
using var conn = new SqliteConnection(cs);
conn.Open();

using var cmd = conn.CreateCommand();

var where = new List<string>();
if (userId is not null)
{
where.Add("user_id = $userId");
cmd.Parameters.AddWithValue("$userId", userId.Value);
}
if (from is not null)
{
where.Add("datum >= $from");
cmd.Parameters.AddWithValue("$from", DateToIso(from.Value));
}
if (to is not null)
{
where.Add("datum <= $to");
cmd.Parameters.AddWithValue("$to", DateToIso(to.Value));
}
if (!string.IsNullOrWhiteSpace(typ) && typ != "all")
{
where.Add("typ = $typ");
cmd.Parameters.AddWithValue("$typ", typ);
}
if (!string.IsNullOrWhiteSpace(q))
{
// fulltext jednoduchý: LIKE na poznámku
where.Add("poznamka LIKE $q");
cmd.Parameters.AddWithValue("$q", "%" + q.Trim() + "%");
}

if (tags is not null && tags.Count > 0)
{
// hledání tagů v CSV (oddělené čárkou) - match na celé tagy
var parts = new List<string>();
for (var i = 0; i < tags.Count; i++)
{
var p = "$tag" + i;
parts.Add($"(',' || ifnull(tagy,'') || ',') LIKE ('%,' || {p} || ',%')");
cmd.Parameters.AddWithValue(p, tags[i]);
}
where.Add("(" + string.Join(" OR ", parts) + ")");
}

var whereSql = where.Count == 0 ? "" : ("WHERE " + string.Join(" AND ", where));

cmd.CommandText = $"""
SELECT id, datum, typ,
poznamka,
tagy,
pocasi,
user_id,
is_public,
cviceni, serie, opakovani, dobaMinuty,
vzdalenostKm, tempo, prevyseniM, tep,
velikostBazenuM, vzdalenostM, dobaPlavaniMin
FROM treninky
{whereSql}
ORDER BY datum DESC, id DESC;
""";

using var r = cmd.ExecuteReader();
while (r.Read())
{
var z = new TreninkovyZaznam
{
Id = r.GetInt32(0),
Datum = IsoToDate(r.GetString(1)),
Typ = r.GetString(2)
};

z.Poznamka = r.IsDBNull(3) ? string.Empty : r.GetString(3);
z.Tagy = r.IsDBNull(4) ? string.Empty : r.GetString(4);
z.Pocasi = r.IsDBNull(5) ? string.Empty : r.GetString(5);
z.UserId = r.IsDBNull(6) ? 0 : r.GetInt32(6);
z.IsPublic = !r.IsDBNull(7) && r.GetInt32(7) == 1;

z.Cviceni = r.IsDBNull(8) ? string.Empty : r.GetString(8);
z.Serie = r.IsDBNull(9) ? 0 : r.GetInt32(9);
z.Opakovani = r.IsDBNull(10) ? 0 : r.GetInt32(10);
z.DobaMinuty = r.IsDBNull(11) ? 0 : r.GetInt32(11);

z.VzdalenostKm = r.IsDBNull(12) ? 0 : r.GetDouble(12);
z.Tempo = r.IsDBNull(13) ? string.Empty : r.GetString(13);
z.PrevyseniM = r.IsDBNull(14) ? 0 : r.GetInt32(14);
z.Tep = r.IsDBNull(15) ? 0 : r.GetInt32(15);

z.VelikostBazenuM = r.IsDBNull(16) ? 0 : r.GetInt32(16);
z.VzdalenostM = r.IsDBNull(17) ? 0 : r.GetInt32(17);
z.DobaPlavaniMin = r.IsDBNull(18) ? 0 : r.GetInt32(18);

res.Add(z);
}

return res;
}

int DbInsert(TreninkovyZaznam z, int? userId)
{
using var conn = new SqliteConnection(cs);
conn.Open();

using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO treninky (
datum, typ,
poznamka,
tagy,
pocasi,
user_id,
is_public,
cviceni, serie, opakovani, dobaMinuty,
vzdalenostKm, tempo, prevyseniM, tep,
velikostBazenuM, vzdalenostM, dobaPlavaniMin
) VALUES (
$datum, $typ,
$poznamka,
$tagy,
$pocasi,
$user_id,
$is_public,
$cviceni, $serie, $opakovani, $dobaMinuty,
$vzdalenostKm, $tempo, $prevyseniM, $tep,
$velikostBazenuM, $vzdalenostM, $dobaPlavaniMin
);
SELECT last_insert_rowid();
""";

cmd.Parameters.AddWithValue("$datum", DateToIso(z.Datum));
cmd.Parameters.AddWithValue("$typ", z.Typ);

cmd.Parameters.AddWithValue("$poznamka", string.IsNullOrWhiteSpace(z.Poznamka) ? (object)DBNull.Value : z.Poznamka);
cmd.Parameters.AddWithValue("$tagy", string.IsNullOrWhiteSpace(z.Tagy) ? (object)DBNull.Value : z.Tagy);
cmd.Parameters.AddWithValue("$pocasi", string.IsNullOrWhiteSpace(z.Pocasi) ? (object)DBNull.Value : z.Pocasi);
cmd.Parameters.AddWithValue("$user_id", userId is null ? (object)DBNull.Value : userId.Value);
cmd.Parameters.AddWithValue("$is_public", z.IsPublic ? 1 : 0);

cmd.Parameters.AddWithValue("$cviceni", string.IsNullOrWhiteSpace(z.Cviceni) ? (object)DBNull.Value : z.Cviceni);
cmd.Parameters.AddWithValue("$serie", z.Serie == 0 ? (object)DBNull.Value : z.Serie);
cmd.Parameters.AddWithValue("$opakovani", z.Opakovani == 0 ? (object)DBNull.Value : z.Opakovani);
cmd.Parameters.AddWithValue("$dobaMinuty", z.DobaMinuty == 0 ? (object)DBNull.Value : z.DobaMinuty);

cmd.Parameters.AddWithValue("$vzdalenostKm", z.VzdalenostKm == 0 ? (object)DBNull.Value : z.VzdalenostKm);
cmd.Parameters.AddWithValue("$tempo", string.IsNullOrWhiteSpace(z.Tempo) ? (object)DBNull.Value : z.Tempo);
cmd.Parameters.AddWithValue("$prevyseniM", z.PrevyseniM == 0 ? (object)DBNull.Value : z.PrevyseniM);
cmd.Parameters.AddWithValue("$tep", z.Tep == 0 ? (object)DBNull.Value : z.Tep);

cmd.Parameters.AddWithValue("$velikostBazenuM", z.VelikostBazenuM == 0 ? (object)DBNull.Value : z.VelikostBazenuM);
cmd.Parameters.AddWithValue("$vzdalenostM", z.VzdalenostM == 0 ? (object)DBNull.Value : z.VzdalenostM);
cmd.Parameters.AddWithValue("$dobaPlavaniMin", z.DobaPlavaniMin == 0 ? (object)DBNull.Value : z.DobaPlavaniMin);

int id = 0;
WithBusyRetry(() => { id = Convert.ToInt32(cmd.ExecuteScalar()); });
return id;
}

TreninkovyZaznam? DbGetById(int id, int? userId)
{
using var conn = new SqliteConnection(cs);
conn.Open();

using var cmd = conn.CreateCommand();
var userFilter = userId is null ? "" : " AND user_id = $userId";
cmd.CommandText = $"""
SELECT id, datum, typ,
poznamka,
tagy,
pocasi,
user_id,
is_public,
cviceni, serie, opakovani, dobaMinuty,
vzdalenostKm, tempo, prevyseniM, tep,
velikostBazenuM, vzdalenostM, dobaPlavaniMin
FROM treninky
WHERE id = $id{userFilter}
LIMIT 1;
""";
cmd.Parameters.AddWithValue("$id", id);
if (userId is not null) cmd.Parameters.AddWithValue("$userId", userId.Value);

using var r = cmd.ExecuteReader();
if (!r.Read()) return null;

var z = new TreninkovyZaznam
{
Id = r.GetInt32(0),
Datum = IsoToDate(r.GetString(1)),
Typ = r.GetString(2)
};

z.Poznamka = r.IsDBNull(3) ? string.Empty : r.GetString(3);
z.Tagy = r.IsDBNull(4) ? string.Empty : r.GetString(4);
z.Pocasi = r.IsDBNull(5) ? string.Empty : r.GetString(5);
z.UserId = r.IsDBNull(6) ? 0 : r.GetInt32(6);
z.IsPublic = !r.IsDBNull(7) && r.GetInt32(7) == 1;

z.Cviceni = r.IsDBNull(8) ? string.Empty : r.GetString(8);
z.Serie = r.IsDBNull(9) ? 0 : r.GetInt32(9);
z.Opakovani = r.IsDBNull(10) ? 0 : r.GetInt32(10);
z.DobaMinuty = r.IsDBNull(11) ? 0 : r.GetInt32(11);

z.VzdalenostKm = r.IsDBNull(12) ? 0 : r.GetDouble(12);
z.Tempo = r.IsDBNull(13) ? string.Empty : r.GetString(13);
z.PrevyseniM = r.IsDBNull(14) ? 0 : r.GetInt32(14);
z.Tep = r.IsDBNull(15) ? 0 : r.GetInt32(15);

z.VelikostBazenuM = r.IsDBNull(16) ? 0 : r.GetInt32(16);
z.VzdalenostM = r.IsDBNull(17) ? 0 : r.GetInt32(17);
z.DobaPlavaniMin = r.IsDBNull(18) ? 0 : r.GetInt32(18);

return z;
}

void DbUpdate(TreninkovyZaznam z, int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();

using var cmd = conn.CreateCommand();
var where = isAdmin ? "WHERE id = $id" : "WHERE id = $id AND user_id = $userId";
cmd.CommandText = $"""
UPDATE treninky SET
datum = $datum,
typ = $typ,
poznamka = $poznamka,
tagy = $tagy,
pocasi = $pocasi,
is_public = $is_public,
cviceni = $cviceni,
serie = $serie,
opakovani = $opakovani,
dobaMinuty = $dobaMinuty,
vzdalenostKm = $vzdalenostKm,
tempo = $tempo,
prevyseniM = $prevyseniM,
tep = $tep,
velikostBazenuM = $velikostBazenuM,
vzdalenostM = $vzdalenostM,
dobaPlavaniMin = $dobaPlavaniMin
{where};
""";

cmd.Parameters.AddWithValue("$id", z.Id);
if (!isAdmin) cmd.Parameters.AddWithValue("$userId", userId);
cmd.Parameters.AddWithValue("$datum", DateToIso(z.Datum));
cmd.Parameters.AddWithValue("$typ", z.Typ);

cmd.Parameters.AddWithValue("$poznamka", string.IsNullOrWhiteSpace(z.Poznamka) ? (object)DBNull.Value : z.Poznamka);
cmd.Parameters.AddWithValue("$tagy", string.IsNullOrWhiteSpace(z.Tagy) ? (object)DBNull.Value : z.Tagy);
cmd.Parameters.AddWithValue("$pocasi", string.IsNullOrWhiteSpace(z.Pocasi) ? (object)DBNull.Value : z.Pocasi);
cmd.Parameters.AddWithValue("$is_public", z.IsPublic ? 1 : 0);

cmd.Parameters.AddWithValue("$cviceni", string.IsNullOrWhiteSpace(z.Cviceni) ? (object)DBNull.Value : z.Cviceni);
cmd.Parameters.AddWithValue("$serie", z.Serie == 0 ? (object)DBNull.Value : z.Serie);
cmd.Parameters.AddWithValue("$opakovani", z.Opakovani == 0 ? (object)DBNull.Value : z.Opakovani);
cmd.Parameters.AddWithValue("$dobaMinuty", z.DobaMinuty == 0 ? (object)DBNull.Value : z.DobaMinuty);

cmd.Parameters.AddWithValue("$vzdalenostKm", z.VzdalenostKm == 0 ? (object)DBNull.Value : z.VzdalenostKm);
cmd.Parameters.AddWithValue("$tempo", string.IsNullOrWhiteSpace(z.Tempo) ? (object)DBNull.Value : z.Tempo);
cmd.Parameters.AddWithValue("$prevyseniM", z.PrevyseniM == 0 ? (object)DBNull.Value : z.PrevyseniM);
cmd.Parameters.AddWithValue("$tep", z.Tep == 0 ? (object)DBNull.Value : z.Tep);

cmd.Parameters.AddWithValue("$velikostBazenuM", z.VelikostBazenuM == 0 ? (object)DBNull.Value : z.VelikostBazenuM);
cmd.Parameters.AddWithValue("$vzdalenostM", z.VzdalenostM == 0 ? (object)DBNull.Value : z.VzdalenostM);
cmd.Parameters.AddWithValue("$dobaPlavaniMin", z.DobaPlavaniMin == 0 ? (object)DBNull.Value : z.DobaPlavaniMin);

WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbInsertPhoto(int treninkId, int? userId, string fileName, string originalName, string contentType)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO trenink_fotky (trenink_id, user_id, file_name, original_name, content_type, created_at)
VALUES ($trenink_id, $user_id, $file_name, $original_name, $content_type, $created_at);
""";
cmd.Parameters.AddWithValue("$trenink_id", treninkId);
cmd.Parameters.AddWithValue("$user_id", userId is null ? (object)DBNull.Value : userId.Value);
cmd.Parameters.AddWithValue("$file_name", fileName);
cmd.Parameters.AddWithValue("$original_name", string.IsNullOrWhiteSpace(originalName) ? (object)DBNull.Value : originalName);
cmd.Parameters.AddWithValue("$content_type", string.IsNullOrWhiteSpace(contentType) ? (object)DBNull.Value : contentType);
cmd.Parameters.AddWithValue("$created_at", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

List<TreninkFoto> DbGetPhotosByRecord(int treninkId, int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
var where = isAdmin ? "" : " AND t.user_id = $userId";
cmd.CommandText = $"""
SELECT f.id, f.trenink_id, f.user_id, f.file_name, f.original_name, f.content_type, f.created_at
FROM trenink_fotky f
JOIN treninky t ON t.id = f.trenink_id
WHERE f.trenink_id = $treninkId{where}
ORDER BY f.id ASC;
""";
cmd.Parameters.AddWithValue("$treninkId", treninkId);
if (!isAdmin) cmd.Parameters.AddWithValue("$userId", userId);
using var r = cmd.ExecuteReader();
var res = new List<TreninkFoto>();
while (r.Read())
{
var foto = new TreninkFoto
{
Id = r.GetInt32(0),
TreninkId = r.GetInt32(1),
UserId = r.IsDBNull(2) ? 0 : r.GetInt32(2),
FileName = r.GetString(3),
OriginalName = r.IsDBNull(4) ? string.Empty : r.GetString(4),
ContentType = r.IsDBNull(5) ? "image/jpeg" : r.GetString(5),
CreatedAt = r.IsDBNull(6) ? string.Empty : r.GetString(6)
};
res.Add(foto);
}
return res;
}

TreninkFoto? DbGetPhotoById(int photoId, int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
var where = isAdmin ? "" : " AND t.user_id = $userId";
cmd.CommandText = $"""
SELECT f.id, f.trenink_id, f.user_id, f.file_name, f.original_name, f.content_type, f.created_at
FROM trenink_fotky f
JOIN treninky t ON t.id = f.trenink_id
WHERE f.id = $id{where}
LIMIT 1;
""";
cmd.Parameters.AddWithValue("$id", photoId);
if (!isAdmin) cmd.Parameters.AddWithValue("$userId", userId);
using var r = cmd.ExecuteReader();
if (!r.Read()) return null;
return new TreninkFoto
{
Id = r.GetInt32(0),
TreninkId = r.GetInt32(1),
UserId = r.IsDBNull(2) ? 0 : r.GetInt32(2),
FileName = r.GetString(3),
OriginalName = r.IsDBNull(4) ? string.Empty : r.GetString(4),
ContentType = r.IsDBNull(5) ? "image/jpeg" : r.GetString(5),
CreatedAt = r.IsDBNull(6) ? string.Empty : r.GetString(6)
};
}

List<CustomType> DbGetCustomTypes(int userId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT id, user_id, key, name, created_at
FROM custom_types
WHERE user_id = $userId
ORDER BY name COLLATE NOCASE;
""";
cmd.Parameters.AddWithValue("$userId", userId);
using var r = cmd.ExecuteReader();
var res = new List<CustomType>();
while (r.Read())
{
res.Add(new CustomType
{
Id = r.GetInt32(0),
UserId = r.GetInt32(1),
Key = r.GetString(2),
Name = r.GetString(3),
CreatedAt = r.IsDBNull(4) ? "" : r.GetString(4)
});
}
return res;
}

List<CustomType> DbGetAllCustomTypes()
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT id, user_id, key, name, created_at
FROM custom_types
ORDER BY user_id, name COLLATE NOCASE;
""";
using var r = cmd.ExecuteReader();
var res = new List<CustomType>();
while (r.Read())
{
res.Add(new CustomType
{
Id = r.GetInt32(0),
UserId = r.GetInt32(1),
Key = r.GetString(2),
Name = r.GetString(3),
CreatedAt = r.IsDBNull(4) ? "" : r.GetString(4)
});
}
return res;
}

CustomType? DbGetCustomTypeByKey(int userId, string key)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT id, user_id, key, name, created_at
FROM custom_types
WHERE user_id = $userId AND key = $key
LIMIT 1;
""";
cmd.Parameters.AddWithValue("$userId", userId);
cmd.Parameters.AddWithValue("$key", key);
using var r = cmd.ExecuteReader();
if (!r.Read()) return null;
return new CustomType
{
Id = r.GetInt32(0),
UserId = r.GetInt32(1),
Key = r.GetString(2),
Name = r.GetString(3),
CreatedAt = r.IsDBNull(4) ? "" : r.GetString(4)
};
}

void DbCreateCustomType(int userId, string key, string name)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO custom_types (user_id, key, name, created_at)
VALUES ($user_id, $key, $name, $created_at);
""";
cmd.Parameters.AddWithValue("$user_id", userId);
cmd.Parameters.AddWithValue("$key", key);
cmd.Parameters.AddWithValue("$name", name);
cmd.Parameters.AddWithValue("$created_at", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

List<CustomField> DbGetCustomFieldsByTypeId(int typeId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT id, type_id, key, label, data_type, unit, min_value, max_value, sort_order
FROM custom_fields
WHERE type_id = $typeId
ORDER BY sort_order ASC, label COLLATE NOCASE;
""";
cmd.Parameters.AddWithValue("$typeId", typeId);
using var r = cmd.ExecuteReader();
var res = new List<CustomField>();
while (r.Read())
{
res.Add(new CustomField
{
Id = r.GetInt32(0),
TypeId = r.GetInt32(1),
Key = r.GetString(2),
Label = r.GetString(3),
DataType = r.GetString(4),
Unit = r.IsDBNull(5) ? null : r.GetString(5),
MinValue = r.IsDBNull(6) ? null : r.GetDouble(6),
MaxValue = r.IsDBNull(7) ? null : r.GetDouble(7),
SortOrder = r.IsDBNull(8) ? 0 : r.GetInt32(8)
});
}
return res;
}

List<CustomField> DbGetCustomFieldsForTypes(List<int> typeIds)
{
if (typeIds.Count == 0) return new List<CustomField>();
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
var placeholders = string.Join(",", typeIds.Select((_, i) => "$t" + i));
cmd.CommandText = $"""
SELECT id, type_id, key, label, data_type, unit, min_value, max_value, sort_order
FROM custom_fields
WHERE type_id IN ({placeholders})
ORDER BY type_id, sort_order ASC, label COLLATE NOCASE;
""";
for (var i = 0; i < typeIds.Count; i++)
{
cmd.Parameters.AddWithValue("$t" + i, typeIds[i]);
}
using var r = cmd.ExecuteReader();
var res = new List<CustomField>();
while (r.Read())
{
res.Add(new CustomField
{
Id = r.GetInt32(0),
TypeId = r.GetInt32(1),
Key = r.GetString(2),
Label = r.GetString(3),
DataType = r.GetString(4),
Unit = r.IsDBNull(5) ? null : r.GetString(5),
MinValue = r.IsDBNull(6) ? null : r.GetDouble(6),
MaxValue = r.IsDBNull(7) ? null : r.GetDouble(7),
SortOrder = r.IsDBNull(8) ? 0 : r.GetInt32(8)
});
}
return res;
}

void DbCreateCustomField(int typeId, string key, string label, string dataType, string? unit, double? minValue, double? maxValue, int sortOrder)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
INSERT INTO custom_fields (type_id, key, label, data_type, unit, min_value, max_value, sort_order)
VALUES ($type_id, $key, $label, $data_type, $unit, $min_value, $max_value, $sort_order);
""";
cmd.Parameters.AddWithValue("$type_id", typeId);
cmd.Parameters.AddWithValue("$key", key);
cmd.Parameters.AddWithValue("$label", label);
cmd.Parameters.AddWithValue("$data_type", dataType);
cmd.Parameters.AddWithValue("$unit", string.IsNullOrWhiteSpace(unit) ? (object)DBNull.Value : unit);
cmd.Parameters.AddWithValue("$min_value", minValue is null ? (object)DBNull.Value : minValue.Value);
cmd.Parameters.AddWithValue("$max_value", maxValue is null ? (object)DBNull.Value : maxValue.Value);
cmd.Parameters.AddWithValue("$sort_order", sortOrder);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbUpdateCustomType(int typeId, string name)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
UPDATE custom_types SET name = $name WHERE id = $id;
""";
cmd.Parameters.AddWithValue("$id", typeId);
cmd.Parameters.AddWithValue("$name", name);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbUpdateCustomField(int fieldId, string label, string dataType, string? unit, double? minValue, double? maxValue, int sortOrder)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
UPDATE custom_fields SET
label = $label,
data_type = $data_type,
unit = $unit,
min_value = $min_value,
max_value = $max_value,
sort_order = $sort_order
WHERE id = $id;
""";
cmd.Parameters.AddWithValue("$id", fieldId);
cmd.Parameters.AddWithValue("$label", label);
cmd.Parameters.AddWithValue("$data_type", dataType);
cmd.Parameters.AddWithValue("$unit", string.IsNullOrWhiteSpace(unit) ? (object)DBNull.Value : unit);
cmd.Parameters.AddWithValue("$min_value", minValue is null ? (object)DBNull.Value : minValue.Value);
cmd.Parameters.AddWithValue("$max_value", maxValue is null ? (object)DBNull.Value : maxValue.Value);
cmd.Parameters.AddWithValue("$sort_order", sortOrder);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

void DbDeleteCustomField(int fieldId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using (var cmd = conn.CreateCommand())
{
cmd.CommandText = "DELETE FROM custom_values WHERE field_id = $id;";
cmd.Parameters.AddWithValue("$id", fieldId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}
using (var cmd = conn.CreateCommand())
{
cmd.CommandText = "DELETE FROM custom_fields WHERE id = $id;";
cmd.Parameters.AddWithValue("$id", fieldId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}
}

void DbDeleteCustomType(int typeId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
var fieldIds = new List<int>();
using (var cmd = conn.CreateCommand())
{
cmd.CommandText = "SELECT id FROM custom_fields WHERE type_id = $id;";
cmd.Parameters.AddWithValue("$id", typeId);
using var r = cmd.ExecuteReader();
while (r.Read()) fieldIds.Add(r.GetInt32(0));
}
if (fieldIds.Count > 0)
{
using var cmdDelVals = conn.CreateCommand();
var placeholders = string.Join(",", fieldIds.Select((_, i) => "$f" + i));
cmdDelVals.CommandText = $"DELETE FROM custom_values WHERE field_id IN ({placeholders});";
for (var i = 0; i < fieldIds.Count; i++) cmdDelVals.Parameters.AddWithValue("$f" + i, fieldIds[i]);
WithBusyRetry(() => cmdDelVals.ExecuteNonQuery());
}
using (var cmdDelFields = conn.CreateCommand())
{
cmdDelFields.CommandText = "DELETE FROM custom_fields WHERE type_id = $id;";
cmdDelFields.Parameters.AddWithValue("$id", typeId);
WithBusyRetry(() => cmdDelFields.ExecuteNonQuery());
}
using (var cmdDelType = conn.CreateCommand())
{
cmdDelType.CommandText = "DELETE FROM custom_types WHERE id = $id;";
cmdDelType.Parameters.AddWithValue("$id", typeId);
WithBusyRetry(() => cmdDelType.ExecuteNonQuery());
}
}

Dictionary<int, string> DbGetCustomValuesByRecord(int recordId)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = """
SELECT field_id, value
FROM custom_values
WHERE trenink_id = $id;
""";
cmd.Parameters.AddWithValue("$id", recordId);
using var r = cmd.ExecuteReader();
var res = new Dictionary<int, string>();
while (r.Read())
{
var fieldId = r.GetInt32(0);
var value = r.IsDBNull(1) ? "" : r.GetString(1);
if (!res.ContainsKey(fieldId)) res[fieldId] = value;
}
return res;
}

Dictionary<int, Dictionary<int, string>> DbGetCustomValuesForRecords(List<int> recordIds)
{
var res = new Dictionary<int, Dictionary<int, string>>();
if (recordIds.Count == 0) return res;
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
var placeholders = string.Join(",", recordIds.Select((_, i) => "$r" + i));
cmd.CommandText = $"""
SELECT trenink_id, field_id, value
FROM custom_values
WHERE trenink_id IN ({placeholders});
""";
for (var i = 0; i < recordIds.Count; i++)
{
cmd.Parameters.AddWithValue("$r" + i, recordIds[i]);
}
using var r = cmd.ExecuteReader();
while (r.Read())
{
var rid = r.GetInt32(0);
var fid = r.GetInt32(1);
var value = r.IsDBNull(2) ? "" : r.GetString(2);
if (!res.TryGetValue(rid, out var map))
{
map = new Dictionary<int, string>();
res[rid] = map;
}
map[fid] = value;
}
return res;
}

void DbReplaceCustomValues(int recordId, Dictionary<int, string> values)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using (var cmdDel = conn.CreateCommand())
{
cmdDel.CommandText = "DELETE FROM custom_values WHERE trenink_id = $id;";
cmdDel.Parameters.AddWithValue("$id", recordId);
WithBusyRetry(() => cmdDel.ExecuteNonQuery());
}

if (values.Count == 0) return;

using var cmdIns = conn.CreateCommand();
cmdIns.CommandText = """
INSERT INTO custom_values (trenink_id, field_id, value)
VALUES ($trenink_id, $field_id, $value);
""";
foreach (var kv in values)
{
cmdIns.Parameters.Clear();
cmdIns.Parameters.AddWithValue("$trenink_id", recordId);
cmdIns.Parameters.AddWithValue("$field_id", kv.Key);
cmdIns.Parameters.AddWithValue("$value", string.IsNullOrWhiteSpace(kv.Value) ? (object)DBNull.Value : kv.Value);
WithBusyRetry(() => cmdIns.ExecuteNonQuery());
}
}

List<TreninkFoto> DbGetPhotosForDelete(int treninkId, int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
var where = isAdmin ? "" : " AND t.user_id = $userId";
cmd.CommandText = $"""
SELECT f.id, f.trenink_id, f.user_id, f.file_name, f.original_name, f.content_type, f.created_at
FROM trenink_fotky f
JOIN treninky t ON t.id = f.trenink_id
WHERE f.trenink_id = $treninkId{where};
""";
cmd.Parameters.AddWithValue("$treninkId", treninkId);
if (!isAdmin) cmd.Parameters.AddWithValue("$userId", userId);
using var r = cmd.ExecuteReader();
var res = new List<TreninkFoto>();
while (r.Read())
{
var foto = new TreninkFoto
{
Id = r.GetInt32(0),
TreninkId = r.GetInt32(1),
UserId = r.IsDBNull(2) ? 0 : r.GetInt32(2),
FileName = r.GetString(3),
OriginalName = r.IsDBNull(4) ? string.Empty : r.GetString(4),
ContentType = r.IsDBNull(5) ? "image/jpeg" : r.GetString(5),
CreatedAt = r.IsDBNull(6) ? string.Empty : r.GetString(6)
};
res.Add(foto);
}
return res;
}

void DbDelete(int id, int userId, bool isAdmin)
{
using var conn = new SqliteConnection(cs);
conn.Open();
var photos = DbGetPhotosForDelete(id, userId, isAdmin);

using (var cmdPhotos = conn.CreateCommand())
{
cmdPhotos.CommandText = isAdmin ? "DELETE FROM trenink_fotky WHERE trenink_id = $id" : "DELETE FROM trenink_fotky WHERE trenink_id = $id AND user_id = $userId";
cmdPhotos.Parameters.AddWithValue("$id", id);
if (!isAdmin) cmdPhotos.Parameters.AddWithValue("$userId", userId);
WithBusyRetry(() => cmdPhotos.ExecuteNonQuery());
}

using (var cmd = conn.CreateCommand())
{
cmd.CommandText = isAdmin ? "DELETE FROM treninky WHERE id = $id" : "DELETE FROM treninky WHERE id = $id AND user_id = $userId";
cmd.Parameters.AddWithValue("$id", id);
if (!isAdmin) cmd.Parameters.AddWithValue("$userId", userId);
WithBusyRetry(() => cmd.ExecuteNonQuery());
}

using (var cmdCustom = conn.CreateCommand())
{
cmdCustom.CommandText = "DELETE FROM custom_values WHERE trenink_id = $id";
cmdCustom.Parameters.AddWithValue("$id", id);
WithBusyRetry(() => cmdCustom.ExecuteNonQuery());
}

foreach (var foto in photos)
{
try
{
var path = Path.Combine(uploadsDir, foto.FileName);
if (File.Exists(path)) File.Delete(path);
}
catch { }
}
}

int DbCount()
{
using var conn = new SqliteConnection(cs);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT COUNT(1) FROM treninky";
return Convert.ToInt32(cmd.ExecuteScalar());
}

InitDb();
EnsureDefaultAdmin();

// Jednorázový import ze starého data.json (pokud existuje) - jen když je DB prázdná.
var legacyJson = Path.Combine(AppContext.BaseDirectory, "data.json");
if (DbCount() == 0 && File.Exists(legacyJson))
{
try
{
var json = File.ReadAllText(legacyJson, Encoding.UTF8);
var imported = JsonSerializer.Deserialize<List<TreninkovyZaznam>>(json) ?? new List<TreninkovyZaznam>();
foreach (var z in imported)
{
// Id ignorujeme, DB si dá vlastní
z.Id = 0;
DbInsert(z, null);
}
File.Move(legacyJson, legacyJson + ".bak", overwrite: true);
}
catch { /* ignore */ }
}

// Dummy data - pouze pokud je DB prázdná
if (DbCount() == 0)
{
var today = DateTime.Today;

DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-12), Typ = "beh", VzdalenostKm = 5.2, Tempo = "5:25", PrevyseniM = 60, Tep = 152 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-10), Typ = "beh", VzdalenostKm = 6.0, Tempo = "5:15", PrevyseniM = 80, Tep = 155 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-8), Typ = "beh", VzdalenostKm = 4.3, Tempo = "5:05", PrevyseniM = 40, Tep = 149 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-6), Typ = "beh", VzdalenostKm = 8.1, Tempo = "5:35", PrevyseniM = 120, Tep = 158 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-4), Typ = "beh", VzdalenostKm = 3.6, Tempo = "4:58", PrevyseniM = 25, Tep = 147 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-2), Typ = "beh", VzdalenostKm = 10.0, Tempo = "5:22", PrevyseniM = 140, Tep = 160 }, null);

DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-11), Typ = "cviceni", Cviceni = "Full body", Serie = 12, Opakovani = 96, DobaMinuty = 55 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-9), Typ = "cviceni", Cviceni = "Hrudník + triceps", Serie = 10, Opakovani = 80, DobaMinuty = 45 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-7), Typ = "cviceni", Cviceni = "Záda + biceps", Serie = 11, Opakovani = 88, DobaMinuty = 50 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-5), Typ = "cviceni", Cviceni = "Nohy", Serie = 9, Opakovani = 72, DobaMinuty = 48 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-3), Typ = "cviceni", Cviceni = "Core", Serie = 8, Opakovani = 64, DobaMinuty = 30 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-1), Typ = "cviceni", Cviceni = "Ramena", Serie = 10, Opakovani = 75, DobaMinuty = 42 }, null);

DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-14), Typ = "kolo", VzdalenostKm = 22.5, DobaMinuty = 68, PrevyseniM = 280, Tep = 148 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-9), Typ = "kolo", VzdalenostKm = 18.2, DobaMinuty = 52, PrevyseniM = 210, Tep = 142 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-5), Typ = "kolo", VzdalenostKm = 35.4, DobaMinuty = 95, PrevyseniM = 420, Tep = 156 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-2), Typ = "kolo", VzdalenostKm = 26.1, DobaMinuty = 72, PrevyseniM = 310, Tep = 151 }, null);

DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-15), Typ = "turistika", VzdalenostKm = 9.5, DobaMinuty = 150, PrevyseniM = 520, Tep = 132 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-8), Typ = "turistika", VzdalenostKm = 12.2, DobaMinuty = 190, PrevyseniM = 640, Tep = 136 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-4), Typ = "turistika", VzdalenostKm = 7.8, DobaMinuty = 120, PrevyseniM = 410, Tep = 128 }, null);

DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-13), Typ = "plavani", VelikostBazenuM = 25, VzdalenostM = 1200, DobaPlavaniMin = 30 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-9), Typ = "plavani", VelikostBazenuM = 25, VzdalenostM = 1500, DobaPlavaniMin = 36 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-6), Typ = "plavani", VelikostBazenuM = 50, VzdalenostM = 1800, DobaPlavaniMin = 40 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-3), Typ = "plavani", VelikostBazenuM = 25, VzdalenostM = 1000, DobaPlavaniMin = 25 }, null);
DbInsert(new TreninkovyZaznam { Datum = today.AddDays(-1), Typ = "plavani", VelikostBazenuM = 25, VzdalenostM = 1600, DobaPlavaniMin = 38 }, null);
}

app.Use(async (context, next) =>
{
var token = context.Request.Cookies[AuthCookieName];
if (!string.IsNullOrWhiteSpace(token))
{
var user = DbGetUserBySession(token);
if (user is not null)
context.Items["user"] = user;
}
await next();
});

app.MapPost("/api/login", async (HttpContext context) =>
{
var req = await JsonSerializer.DeserializeAsync<LoginRequest>(context.Request.Body);
if (req is null) return Results.BadRequest(new { error = "invalid_payload" });

var (user, hash) = DbGetUserWithHash(req.Username ?? "");
if (user is null || string.IsNullOrWhiteSpace(hash) || !VerifyPassword(req.Password ?? "", hash))
return Results.Unauthorized();

var token = DbCreateSession(user.Id, out var expiresAt);
SetAuthCookie(context, token, expiresAt);
ClaimLegacyRecords(user.Id);
return Results.Json(new { ok = true, username = user.Username, isAdmin = user.IsAdmin });
});

app.MapPost("/api/register", async (HttpContext context) =>
{
var req = await JsonSerializer.DeserializeAsync<RegisterRequest>(context.Request.Body);
if (req is null) return Results.BadRequest(new { error = "invalid_payload" });
var username = (req.Username ?? "").Trim();
if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(req.Password))
return Results.BadRequest(new { error = "missing_fields" });
if (req.Password != (req.Password2 ?? ""))
return Results.BadRequest(new { error = "password_mismatch" });
if (DbGetUserByUsername(username) is not null)
return Results.BadRequest(new { error = "user_exists" });

var hash = HashPassword(req.Password);
var isAdmin = DbUsersCount() == 0;
var userId = DbCreateUser(username, hash, isAdmin);
var token = DbCreateSession(userId, out var expiresAt);
SetAuthCookie(context, token, expiresAt);
ClaimLegacyRecords(userId);
return Results.Json(new { ok = true, username, isAdmin });
});

app.MapPost("/api/logout", (HttpContext context) =>
{
var token = context.Request.Cookies[AuthCookieName];
if (!string.IsNullOrWhiteSpace(token))
DbDeleteSession(token);
context.Response.Cookies.Delete(AuthCookieName);
return Results.Json(new { ok = true });
});

app.MapGet("/api/me", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();
return Results.Json(new { username = user.Username, isAdmin = user.IsAdmin });
});

app.MapGet("/api/records", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();

var request = context.Request;
var qsFrom = request.Query["from"].ToString();
var qsTo = request.Query["to"].ToString();
var qsTyp = (request.Query["typ"].ToString() ?? "").Trim();
var qsQ = request.Query["q"].ToString();
var selTags = request.Query["tag"].ToArray().Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList();
var qsUser = request.Query["user"].ToString();

DateTime? from = null;
DateTime? to = null;
if (!string.IsNullOrWhiteSpace(qsFrom)) from = IsoToDate(qsFrom);
if (!string.IsNullOrWhiteSpace(qsTo)) to = IsoToDate(qsTo);
if (string.IsNullOrWhiteSpace(qsTyp)) qsTyp = "all";

int? userFilterId = user.IsAdmin ? null : user.Id;
if (user.IsAdmin && int.TryParse(qsUser, out var uid)) userFilterId = uid;

var zaznamy = DbQuery(userFilterId, from, to, qsTyp, qsQ, selTags.Count == 0 ? null : selTags);
return Results.Json(zaznamy.Select(ToApiRecord));
});

app.MapGet("/api/records/{id:int}", (HttpContext context, int id) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();
var z = DbGetById(id, user.IsAdmin ? null : user.Id);
if (z is null) return Results.NotFound();
return Results.Json(ToApiRecord(z));
});

app.MapPost("/api/records", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();
var input = await JsonSerializer.DeserializeAsync<ApiRecordInput>(context.Request.Body);
if (input is null) return Results.BadRequest(new { error = "invalid_payload" });

var z = FromApiRecord(input);
var newId = DbInsert(z, user.Id);
var created = DbGetById(newId, user.Id);
return Results.Json(created is null ? new { id = newId } : ToApiRecord(created));
});

app.MapPut("/api/records/{id:int}", async (HttpContext context, int id) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();
var existing = DbGetById(id, user.IsAdmin ? null : user.Id);
if (existing is null) return Results.NotFound();

var input = await JsonSerializer.DeserializeAsync<ApiRecordInput>(context.Request.Body);
if (input is null) return Results.BadRequest(new { error = "invalid_payload" });

var updated = FromApiRecord(input, id);
DbUpdate(updated, user.Id, user.IsAdmin);
var z = DbGetById(id, user.IsAdmin ? null : user.Id);
return Results.Json(z is null ? new { id } : ToApiRecord(z));
});

app.MapDelete("/api/records/{id:int}", (HttpContext context, int id) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Unauthorized();
DbDelete(id, user.Id, user.IsAdmin);
return Results.Json(new { ok = true });
});

app.MapGet("/login", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is not null) return Results.Redirect("/");

var body = new StringBuilder();
body.Append("""
<h2>Přihlášení</h2>
<form method="post" action="/login">
<div class="grid">
<div class="field">
<label for="username">Uživatelské jméno</label>
<input id="username" name="username" type="text" autocomplete="username" required />
</div>
<div class="field">
<label for="password">Heslo</label>
<input id="password" name="password" type="password" autocomplete="current-password" required />
</div>
</div>
<div class="actions">
<button type="submit">Přihlásit se</button>
<a class="btn-secondary" href="/register" style="display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none">Registrovat se</a>
</div>
</form>
""");

return Results.Content(PageLayout("Přihlášení", body.ToString()), "text/html; charset=utf-8");
});

app.MapPost("/login", async (HttpContext context) =>
{
var form = await context.Request.ReadFormAsync();
var username = (form["username"].ToString() ?? "").Trim();
var password = form["password"].ToString();

var (user, hash) = DbGetUserWithHash(username);
if (user is null || string.IsNullOrWhiteSpace(hash) || !VerifyPassword(password, hash))
{
var body = "<h2>Přihlášení</h2><p style=\"color:#b91c1c\">Neplatné přihlašovací údaje.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/login\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Přihlášení", body), "text/html; charset=utf-8");
}

var token = DbCreateSession(user.Id, out var expiresAt);
SetAuthCookie(context, token, expiresAt);
ClaimLegacyRecords(user.Id);
return Results.Redirect("/");
});

app.MapGet("/register", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is not null) return Results.Redirect("/");

var body = new StringBuilder();
body.Append("""
<h2>Registrace</h2>
<form method="post" action="/register">
<div class="grid">
<div class="field">
<label for="username">Uživatelské jméno</label>
<input id="username" name="username" type="text" autocomplete="username" required />
</div>
<div class="field">
<label for="password">Heslo</label>
<input id="password" name="password" type="password" autocomplete="new-password" required />
</div>
<div class="field">
<label for="password2">Heslo znovu</label>
<input id="password2" name="password2" type="password" autocomplete="new-password" required />
</div>
</div>
<div class="actions">
<button type="submit">Vytvořit účet</button>
<a class="btn-secondary" href="/login" style="display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none">Už mám účet</a>
</div>
</form>
""");

return Results.Content(PageLayout("Registrace", body.ToString()), "text/html; charset=utf-8");
});

app.MapPost("/register", async (HttpContext context) =>
{
var form = await context.Request.ReadFormAsync();
var username = (form["username"].ToString() ?? "").Trim();
var password = form["password"].ToString();
var password2 = form["password2"].ToString();

if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
{
var body = "<h2>Registrace</h2><p style=\"color:#b91c1c\">Vyplň uživatelské jméno a heslo.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/register\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Registrace", body), "text/html; charset=utf-8");
}
if (password != password2)
{
var body = "<h2>Registrace</h2><p style=\"color:#b91c1c\">Hesla se neshodují.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/register\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Registrace", body), "text/html; charset=utf-8");
}
if (DbGetUserByUsername(username) is not null)
{
var body = "<h2>Registrace</h2><p style=\"color:#b91c1c\">Uživatel už existuje.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/register\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Registrace", body), "text/html; charset=utf-8");
}

var hash = HashPassword(password);
var isAdmin = DbUsersCount() == 0;
var userId = DbCreateUser(username, hash, isAdmin);
var token = DbCreateSession(userId, out var expiresAt);
SetAuthCookie(context, token, expiresAt);
ClaimLegacyRecords(userId);
return Results.Redirect("/");
});

app.MapGet("/logout", (HttpContext context) =>
{
var token = context.Request.Cookies[AuthCookieName];
if (!string.IsNullOrWhiteSpace(token))
DbDeleteSession(token);
context.Response.Cookies.Delete(AuthCookieName);
return Results.Redirect("/login");
});

app.MapGet("/account", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");

var body = new StringBuilder();
body.Append("""
<h2>Můj účet</h2>
<form method="post" action="/account/password">
<h3>Změna hesla</h3>
<div class="grid">
<div class="field">
<label for="current">Současné heslo</label>
<input id="current" name="current" type="password" autocomplete="current-password" required />
</div>
<div class="field">
<label for="newpass">Nové heslo</label>
<input id="newpass" name="newpass" type="password" autocomplete="new-password" required />
</div>
<div class="field">
<label for="newpass2">Nové heslo znovu</label>
<input id="newpass2" name="newpass2" type="password" autocomplete="new-password" required />
</div>
</div>
<div class="actions">
<button type="submit">Změnit heslo</button>
</div>
</form>
<hr style="margin:1rem 0; border:none; border-top:1px solid var(--border)" />
<form method="post" action="/account/logout-all" onsubmit="return confirm('Opravdu odhlásit všechna zařízení?')">
<h3>Odhlásit všechna zařízení</h3>
<div class="actions">
<button class="btn-secondary" type="submit">Odhlásit všechna zařízení</button>
</div>
</form>
<hr style="margin:1rem 0; border:none; border-top:1px solid var(--border)" />
<h3>Export / Import</h3>
<p style="color:#64748b; margin-top:-0.4rem">CSV exportuje všechny vaše záznamy. Import přidá nové záznamy, včetně vlastních atributů (sloupce ve tvaru <b>custom_typ_klíč</b>).</p>
<div class="actions" style="display:flex; gap:0.5rem; flex-wrap:wrap">
<a class="btn-secondary" href="/export" style="display:inline-flex; align-items:center; gap:0.45rem; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none">
<span class="icon-inline" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M12 3v12"></path>
<path d="M8 11l4 4 4-4"></path>
<path d="M4 21h16"></path>
</svg>
</span>
Export CSV
</a>
<a class="btn-secondary" href="/typy" style="display:inline-flex; align-items:center; gap:0.45rem; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none">
<span class="icon-inline" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M12 4v16"></path>
<path d="M4 12h16"></path>
</svg>
</span>
Správa typů
</a>
</div>
<form method="post" action="/import" enctype="multipart/form-data" style="margin-top:0.75rem">
<div class="field" style="max-width:520px">
<label for="csv">Import CSV</label>
<input id="csv" class="file-input" type="file" name="csv" accept=".csv,text/csv" required />
<label class="btn-secondary file-label" for="csv">
<span class="icon-inline" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M12 3v12"></path>
<path d="M8 11l4 4 4-4"></path>
<path d="M4 21h16"></path>
</svg>
</span>
Zvolit soubor
</label>
<div style="font-size:0.85rem; color: var(--muted); margin-top:0.35rem">Očekávané hlavičky: datum, typ, poznamka, tagy, pocasi, cviceni, serie, opakovani, dobaMinuty, vzdalenostKm, tempo, prevyseniM, tep, velikostBazenuM, vzdalenostM, dobaPlavaniMin, custom_typ_klíč</div>
</div>
<div class="actions">
<button type="submit">Importovat</button>
</div>
</form>
""");

return Results.Content(PageLayout("Můj účet", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/typy", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var qsUser = context.Request.Query["user"].ToString();

User? targetUser = null;
var viewUserId = user.Id;
var readOnly = false;
if (user.IsAdmin && int.TryParse(qsUser, out var uid))
{
targetUser = DbGetUserById(uid);
if (targetUser is not null)
{
viewUserId = targetUser.Id;
readOnly = targetUser.Id != user.Id;
}
}

var types = DbGetCustomTypes(viewUserId);
var fields = DbGetCustomFieldsForTypes(types.Select(t => t.Id).ToList());
var fieldsByType = fields.GroupBy(f => f.TypeId).ToDictionary(g => g.Key, g => g.ToList());

var body = new StringBuilder();
body.Append("<h2>Vlastní typy cvičení</h2>");
if (user.IsAdmin && targetUser is not null)
{
body.Append($"<p style=\"color:#64748b; margin:0 0 0.75rem\">Uživatel: <b>{H(targetUser.Username)}</b> (<a href=\"/typy\" style=\"color:#2563eb; text-decoration:none\">moje typy</a>)</p>");
}
body.Append("<p style=\"color:#64748b; margin-top:-0.35rem\">Definujte si vlastní typy a atributy. Atributy lze použít v novém záznamu i ve statistikách.</p>");

if (!readOnly)
{
body.Append("<hr style=\"margin:1rem 0; border:none; border-top:1px solid var(--border)\" />");
body.Append("<h3>Nový typ</h3>");
var err = context.Request.Query["error"].ToString();
if (err == "type_exists")
{
body.Append("<p style=\"color:#b91c1c; margin-top:-0.4rem\">Tento druh cvičení již existuje.</p>");
}
body.Append("<form method=\"post\" action=\"/typy/type\">");
body.Append("<div class=\"grid\">");
body.Append("<div class=\"field\"><label for=\"type_name\">Název</label><input id=\"type_name\" name=\"name\" type=\"text\" required /></div>");
body.Append("<div class=\"field\"><label for=\"type_key\">Klíč (volitelný)</label><input id=\"type_key\" name=\"key\" type=\"text\" placeholder=\"např. yoga\" /></div>");
body.Append("</div>");
body.Append("<div class=\"actions\"><button type=\"submit\">Přidat typ</button></div>");
body.Append("</form>");

body.Append("<hr style=\"margin:1rem 0; border:none; border-top:1px solid var(--border)\" />");
body.Append("<h3>Nový atribut</h3>");
if (types.Count == 0)
{
body.Append("<p style=\"color:#64748b\">Nejdřív vytvořte alespoň jeden typ.</p>");
}
else
{
body.Append("<form method=\"post\" action=\"/typy/field\">");
body.Append("<div class=\"grid\">");
body.Append("<div class=\"field\"><label for=\"field_type\">Typ</label><select id=\"field_type\" name=\"type_id\">");
foreach (var t in types) body.Append($"<option value=\"{t.Id}\">{H(t.Name)}</option>");
body.Append("</select></div>");
body.Append("<div class=\"field\"><label for=\"field_label\">Název</label><input id=\"field_label\" name=\"label\" type=\"text\" required /></div>");
body.Append("<div class=\"field\"><label for=\"field_key\">Klíč (volitelný)</label><input id=\"field_key\" name=\"key\" type=\"text\" placeholder=\"např. tep\" /></div>");
body.Append("<div class=\"field\"><label for=\"field_type_select\">Typ hodnoty</label><select id=\"field_type_select\" name=\"data_type\"><option value=\"number\">číslo</option><option value=\"text\">text</option><option value=\"bool\">ano/ne</option></select></div>");
body.Append("<div class=\"field\"><label for=\"field_unit\">Jednotka</label><select id=\"field_unit\" name=\"unit\"><option value=\"\">bez</option><option value=\"km\">km</option><option value=\"m\">m</option><option value=\"min\">min</option><option value=\"s\">s</option><option value=\"kg\">kg</option><option value=\"kcal\">kcal</option><option value=\"bpm\">bpm</option><option value=\"%\">%</option><option value=\"opak\">opak.</option></select></div>");
body.Append("<div class=\"field\"><label for=\"field_min\">Min</label><input id=\"field_min\" name=\"min\" type=\"number\" step=\"0.01\" /></div>");
body.Append("<div class=\"field\"><label for=\"field_max\">Max</label><input id=\"field_max\" name=\"max\" type=\"number\" step=\"0.01\" /></div>");
body.Append("<div class=\"field\"><label for=\"field_sort\">Řazení</label><input id=\"field_sort\" name=\"sort\" type=\"number\" value=\"0\" /></div>");
body.Append("</div>");
body.Append("<div class=\"actions\"><button type=\"submit\">Přidat atribut</button></div>");
body.Append("</form>");
}
}
else
{
body.Append("<p style=\"color:#64748b; margin-top:0.75rem\">Zobrazené je jen pro čtení.</p>");
}

body.Append("<hr style=\"margin:1.25rem 0; border:none; border-top:1px solid var(--border)\" />");
body.Append("<h3>Moje sporty</h3>");

if (types.Count == 0)
{
body.Append("<p>Zatím nemáte žádné vlastní typy.</p>");
}
else
{
foreach (var t in types)
{
var bodyId = $"type-{t.Id}";
body.Append("<div class=\"card\" style=\"margin-top:0.75rem; overflow:hidden\">");
body.Append($"<div class=\"type-head\" data-target=\"{bodyId}\" style=\"cursor:pointer; padding:0.8rem 0.9rem; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--border)\">");
body.Append("<div>");
body.Append($"<div style=\"font-weight:800\">{H(t.Name)}</div>");
body.Append($"<div style=\"color:#64748b; font-size:0.9rem\">Klíč: <b>{H(t.Key)}</b></div>");
body.Append("</div>");
body.Append("<span class=\"type-caret\" style=\"font-size:1.1rem; color:#64748b; display:inline-block; transform:rotate(0deg)\">?</span>");
body.Append("</div>");
body.Append($"<div id=\"{bodyId}\" class=\"type-body\" style=\"display:none; padding:0 0.9rem 0.9rem\">");
if (!readOnly)
{
body.Append("<div style=\"margin-top:0.5rem; display:flex; gap:0.5rem; flex-wrap:wrap; align-items:flex-end\">");
body.Append("<form method=\"post\" action=\"/typy/type/edit\" style=\"display:flex; gap:0.5rem; align-items:flex-end\">");
body.Append($"<input type=\"hidden\" name=\"type_id\" value=\"{t.Id}\" />");
body.Append("<div class=\"field\" style=\"min-width:220px\"><label>Upravit název</label>");
body.Append($"<input name=\"name\" type=\"text\" value=\"{H(t.Name)}\" required /></div>");
body.Append("<div class=\"actions\" style=\"margin:0\"><button type=\"submit\">Uložit</button></div>");
body.Append("</form>");
body.Append("<form method=\"post\" action=\"/typy/type/delete\" onsubmit=\"return confirm('Smazat typ i jeho atributy?')\">");
body.Append($"<input type=\"hidden\" name=\"type_id\" value=\"{t.Id}\" />");
body.Append("<button class=\"btn-secondary\" type=\"submit\">Smazat typ</button>");
body.Append("</form>");
body.Append("</div>");
}
body.Append("<div style=\"margin-top:0.5rem\">");
if (!fieldsByType.TryGetValue(t.Id, out var fl) || fl.Count == 0)
{
body.Append("<p style=\"color:#64748b; margin:0\">Bez atributů.</p>");
}
else if (readOnly)
{
foreach (var f in fl)
{
var unitText = H(f.Unit ?? "");
var minText = f.MinValue is null ? "" : H(f.MinValue.Value.ToString("0.##", CultureInfo.InvariantCulture));
var maxText = f.MaxValue is null ? "" : H(f.MaxValue.Value.ToString("0.##", CultureInfo.InvariantCulture));
body.Append("<div class=\"card\" style=\"margin-top:0.6rem; padding:0.75rem\">");
body.Append("<div class=\"grid\">");
body.Append("<div class=\"field\"><label>Název</label><input type=\"text\" value=\"" + H(f.Label) + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Klíč</label><input type=\"text\" value=\"" + H(f.Key) + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Typ</label><input type=\"text\" value=\"" + H(f.DataType) + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Jednotka</label><input type=\"text\" value=\"" + unitText + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Min</label><input type=\"text\" value=\"" + minText + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Max</label><input type=\"text\" value=\"" + maxText + "\" readonly /></div>");
body.Append("</div>");
body.Append("</div>");
}
}
else
{
foreach (var f in fl)
{
var formId = $"field-edit-{f.Id}";
var delFormId = $"field-del-{f.Id}";
var minText = f.MinValue is null ? "" : H(f.MinValue.Value.ToString("0.##", CultureInfo.InvariantCulture));
var maxText = f.MaxValue is null ? "" : H(f.MaxValue.Value.ToString("0.##", CultureInfo.InvariantCulture));
body.Append("<div class=\"card\" style=\"margin-top:0.6rem; padding:0.75rem\">");
body.Append($"<form id=\"{formId}\" method=\"post\" action=\"/typy/field/edit\"></form>");
body.Append("<div class=\"grid\">");
body.Append($"<div class=\"field\"><label>Název</label><input name=\"label\" form=\"{formId}\" type=\"text\" value=\"{H(f.Label)}\" /></div>");
body.Append("<div class=\"field\"><label>Klíč</label><input type=\"text\" value=\"" + H(f.Key) + "\" readonly /></div>");
body.Append("<div class=\"field\"><label>Typ</label>");
body.Append($"<select name=\"data_type\" form=\"{formId}\">");
var selectedNumber = f.DataType == "number" ? "selected" : "";
var selectedText = f.DataType == "text" ? "selected" : "";
var selectedBool = f.DataType == "bool" ? "selected" : "";
body.Append("<option value=\"number\" " + selectedNumber + ">číslo</option>");
body.Append("<option value=\"text\" " + selectedText + ">text</option>");
body.Append("<option value=\"bool\" " + selectedBool + ">ano/ne</option>");
body.Append("</select>");
body.Append("</div>");
body.Append("<div class=\"field\"><label>Jednotka</label>");
body.Append($"<select name=\"unit\" form=\"{formId}\">");
string UnitOpt(string v, string label)
{
var selected = string.Equals(f.Unit ?? "", v, StringComparison.OrdinalIgnoreCase) ? "selected" : "";
return "<option value=\"" + v + "\" " + selected + ">" + label + "</option>";
}
body.Append(UnitOpt("", "bez"));
body.Append(UnitOpt("km", "km"));
body.Append(UnitOpt("m", "m"));
body.Append(UnitOpt("min", "min"));
body.Append(UnitOpt("s", "s"));
body.Append(UnitOpt("kg", "kg"));
body.Append(UnitOpt("kcal", "kcal"));
body.Append(UnitOpt("bpm", "bpm"));
body.Append(UnitOpt("%", "%"));
body.Append(UnitOpt("opak", "opak."));
body.Append("</select>");
body.Append("</div>");
body.Append("<div class=\"field\"><label>Min</label><input name=\"min\" form=\"" + formId + "\" type=\"number\" step=\"0.01\" value=\"" + minText + "\" /></div>");
body.Append("<div class=\"field\"><label>Max</label><input name=\"max\" form=\"" + formId + "\" type=\"number\" step=\"0.01\" value=\"" + maxText + "\" /></div>");
body.Append($"<div class=\"field\"><label>Řazení</label><input name=\"sort\" form=\"{formId}\" type=\"number\" value=\"{f.SortOrder}\" /></div>");
body.Append("</div>");
body.Append("<div class=\"actions\" style=\"display:flex; gap:0.5rem; margin-top:0.5rem\">");
body.Append($"<input type=\"hidden\" form=\"{formId}\" name=\"field_id\" value=\"{f.Id}\" />");
body.Append($"<input type=\"hidden\" form=\"{formId}\" name=\"type_id\" value=\"{t.Id}\" />");
body.Append($"<button type=\"submit\" form=\"{formId}\">Uložit</button>");
body.Append($"<form id=\"{delFormId}\" method=\"post\" action=\"/typy/field/delete\" style=\"display:inline\" onsubmit=\"return confirm('Smazat atribut?')\"></form>");
body.Append($"<input type=\"hidden\" form=\"{delFormId}\" name=\"field_id\" value=\"{f.Id}\" />");
body.Append($"<input type=\"hidden\" form=\"{delFormId}\" name=\"type_id\" value=\"{t.Id}\" />");
body.Append($"<button class=\"btn-secondary\" type=\"submit\" form=\"{delFormId}\">Smazat</button>");
body.Append("</div>");
body.Append("</div>");
}
}
body.Append("</div>");
body.Append("</div>");
body.Append("</div>");
}
}
body.Append("""
<script>
document.querySelectorAll('.type-head').forEach(function(h) {
  h.setAttribute('tabindex','0');
  h.setAttribute('role','button');
  var caret = h.querySelector('.type-caret');
  function toggle() {
    var id = h.getAttribute('data-target');
    var body = document.getElementById(id);
    if (!body) return;
    var open = body.style.display === 'block';
    body.style.display = open ? 'none' : 'block';
    if (caret) caret.style.transform = open ? 'rotate(0deg)' : 'rotate(90deg)';
  }
  h.addEventListener('click', toggle);
  h.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
  });
});
</script>
""");
return Results.Content(PageLayout("Vlastní typy", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapPost("/typy/type", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
var name = (form["name"].ToString() ?? "").Trim();
var keyInput = (form["key"].ToString() ?? "").Trim();
if (string.IsNullOrWhiteSpace(name)) return Results.Redirect("/typy");
var types = DbGetCustomTypes(user.Id);
if (types.Any(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)) ||
    BuiltInTypes.Any(t => string.Equals(t.Label, name, StringComparison.OrdinalIgnoreCase)))
{
return Results.Redirect("/typy?error=type_exists");
}
var key = string.IsNullOrWhiteSpace(keyInput) ? NormalizeKey(name) : NormalizeKey(keyInput);
if (IsBuiltInType(key)) key = "custom_" + key;

var existing = DbGetCustomTypeByKey(user.Id, key);
if (existing is null)
{
DbCreateCustomType(user.Id, key, name);
}
return Results.Redirect("/typy");
});

app.MapPost("/typy/field", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["type_id"].ToString(), out var typeId)) return Results.Redirect("/typy");
var label = (form["label"].ToString() ?? "").Trim();
var keyInput = (form["key"].ToString() ?? "").Trim();
var dataType = (form["data_type"].ToString() ?? "text").Trim().ToLowerInvariant();
var unit = NormalizeUnit(form["unit"].ToString());
var minText = form["min"].ToString();
var maxText = form["max"].ToString();
var sortText = form["sort"].ToString();
var hasMin = !string.IsNullOrWhiteSpace(minText);
var hasMax = !string.IsNullOrWhiteSpace(maxText);
var min = ParseDouble(minText);
var max = ParseDouble(maxText);
var sort = ParseInt(sortText);
if (string.IsNullOrWhiteSpace(label)) return Results.Redirect("/typy");

var types = DbGetCustomTypes(user.Id);
if (!types.Any(t => t.Id == typeId)) return Results.Redirect("/typy");

if (dataType != "number" && dataType != "text" && dataType != "bool") dataType = "text";
var key = string.IsNullOrWhiteSpace(keyInput) ? NormalizeKey(label) : NormalizeKey(keyInput);
DbCreateCustomField(typeId, key, label, dataType, unit, hasMin ? min : (double?)null, hasMax ? max : (double?)null, sort);
return Results.Redirect("/typy");
});

app.MapPost("/typy/type/edit", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["type_id"].ToString(), out var typeId)) return Results.Redirect("/typy");
var name = (form["name"].ToString() ?? "").Trim();
if (string.IsNullOrWhiteSpace(name)) return Results.Redirect("/typy");
var types = DbGetCustomTypes(user.Id);
if (!types.Any(t => t.Id == typeId)) return Results.Redirect("/typy");
DbUpdateCustomType(typeId, name);
return Results.Redirect("/typy");
});

app.MapPost("/typy/type/delete", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["type_id"].ToString(), out var typeId)) return Results.Redirect("/typy");
var types = DbGetCustomTypes(user.Id);
if (!types.Any(t => t.Id == typeId)) return Results.Redirect("/typy");
DbDeleteCustomType(typeId);
return Results.Redirect("/typy");
});

app.MapPost("/typy/field/edit", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["type_id"].ToString(), out var typeId)) return Results.Redirect("/typy");
if (!int.TryParse(form["field_id"].ToString(), out var fieldId)) return Results.Redirect("/typy");
var label = (form["label"].ToString() ?? "").Trim();
var dataType = (form["data_type"].ToString() ?? "text").Trim().ToLowerInvariant();
var unit = NormalizeUnit(form["unit"].ToString());
var minText = form["min"].ToString();
var maxText = form["max"].ToString();
var hasMin = !string.IsNullOrWhiteSpace(minText);
var hasMax = !string.IsNullOrWhiteSpace(maxText);
var min = ParseDouble(minText);
var max = ParseDouble(maxText);
var sortText = form["sort"].ToString();
var sort = ParseInt(sortText);
if (string.IsNullOrWhiteSpace(label)) return Results.Redirect("/typy");
var types = DbGetCustomTypes(user.Id);
if (!types.Any(t => t.Id == typeId)) return Results.Redirect("/typy");
var fields = DbGetCustomFieldsByTypeId(typeId);
if (!fields.Any(f => f.Id == fieldId)) return Results.Redirect("/typy");
if (dataType != "number" && dataType != "text" && dataType != "bool") dataType = "text";
DbUpdateCustomField(fieldId, label, dataType, unit, hasMin ? min : (double?)null, hasMax ? max : (double?)null, sort);
return Results.Redirect("/typy");
});

app.MapPost("/typy/field/delete", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["type_id"].ToString(), out var typeId)) return Results.Redirect("/typy");
if (!int.TryParse(form["field_id"].ToString(), out var fieldId)) return Results.Redirect("/typy");
var types = DbGetCustomTypes(user.Id);
if (!types.Any(t => t.Id == typeId)) return Results.Redirect("/typy");
var fields = DbGetCustomFieldsByTypeId(typeId);
if (!fields.Any(f => f.Id == fieldId)) return Results.Redirect("/typy");
DbDeleteCustomField(fieldId);
return Results.Redirect("/typy");
});

app.MapPost("/account/password", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");

var form = await context.Request.ReadFormAsync();
var current = form["current"].ToString();
var newpass = form["newpass"].ToString();
var newpass2 = form["newpass2"].ToString();

if (string.IsNullOrWhiteSpace(newpass) || newpass != newpass2)
{
var body = "<h2>Můj účet</h2><p style=\"color:#b91c1c\">Nová hesla se neshodují.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/account\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Můj účet", body, user.Username, user.IsAdmin), "text/html; charset=utf-8");
}

var (_, hash) = DbGetUserWithHash(user.Username);
if (string.IsNullOrWhiteSpace(hash) || !VerifyPassword(current, hash))
{
var body = "<h2>Můj účet</h2><p style=\"color:#b91c1c\">Současné heslo nesedí.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/account\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Můj účet", body, user.Username, user.IsAdmin), "text/html; charset=utf-8");
}

var newHash = HashPassword(newpass);
DbUpdateUserPassword(user.Id, newHash);
DbDeleteSessionsForUser(user.Id);
var token = DbCreateSession(user.Id, out var expiresAt);
SetAuthCookie(context, token, expiresAt);
return Results.Redirect("/account");
});

app.MapPost("/account/logout-all", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
DbDeleteSessionsForUser(user.Id);
context.Response.Cookies.Delete(AuthCookieName);
return Results.Redirect("/login");
});

app.MapGet("/export", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var zaznamy = DbGetAll(user.IsAdmin ? (int?)null : user.Id).OrderBy(z => z.Datum).ToList();
var customTypes = user.IsAdmin ? new List<CustomType>() : DbGetCustomTypes(user.Id);
var customFields = DbGetCustomFieldsForTypes(customTypes.Select(t => t.Id).ToList());
var customValues = customTypes.Count == 0 ? new Dictionary<int, Dictionary<int, string>>() : DbGetCustomValuesForRecords(zaznamy.Select(z => z.Id).ToList());
var csv = BuildCsv(zaznamy, customTypes, customFields, customValues);
var bytes = Encoding.UTF8.GetBytes("\uFEFF" + csv);
var fileName = $"treninky_export_{DateTime.Today:yyyyMMdd}.csv";
return Results.File(bytes, "text/csv; charset=utf-8", fileName);
});

app.MapPost("/import", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
var file = form.Files.GetFile("csv");
if (file is null || file.Length == 0)
{
var body = "<h2>Import</h2><p style=\"color:#b91c1c\">Soubor CSV nebyl nalezen.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/account\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Import", body, user.Username, user.IsAdmin), "text/html; charset=utf-8");
}

string csvText;
using (var reader = new StreamReader(file.OpenReadStream(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false))
{
csvText = await reader.ReadToEndAsync();
}

var rows = ParseCsvRows(csvText);
if (rows.Count == 0)
{
var body = "<h2>Import</h2><p style=\"color:#b91c1c\">CSV neobsahuje data.</p>";
body += "<p><a class=\"btn-secondary\" href=\"/account\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a></p>";
return Results.Content(PageLayout("Import", body, user.Username, user.IsAdmin), "text/html; charset=utf-8");
}

var header = rows[0].Select(h => (h ?? "").Trim()).ToList();
if (header.Count > 0 && header[0].StartsWith("\uFEFF", StringComparison.Ordinal))
{
header[0] = header[0].TrimStart('\uFEFF');
}
var col = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
for (var i = 0; i < header.Count; i++)
{
if (!string.IsNullOrWhiteSpace(header[i])) col[header[i]] = i;
}

var userCustomTypes = DbGetCustomTypes(user.Id);
var customTypeByKey = userCustomTypes.ToDictionary(t => t.Key, t => t, StringComparer.OrdinalIgnoreCase);
var typeKeyById = userCustomTypes.ToDictionary(t => t.Id, t => t.Key);
var customFields = DbGetCustomFieldsForTypes(userCustomTypes.Select(t => t.Id).ToList());
var customFieldByTypeKeyAndFieldKey = new Dictionary<(string, string), CustomField>();
foreach (var f in customFields)
{
if (!typeKeyById.TryGetValue(f.TypeId, out var typeKey)) continue;
customFieldByTypeKeyAndFieldKey[(typeKey.ToLowerInvariant(), f.Key.ToLowerInvariant())] = f;
}
var customColumns = new List<(int Index, string TypeKey, CustomField Field)>();
for (var i = 0; i < header.Count; i++)
{
if (!TryParseCustomHeader(header[i], out var typeKey, out var fieldKey)) continue;
if (!customFieldByTypeKeyAndFieldKey.TryGetValue((typeKey.ToLowerInvariant(), fieldKey.ToLowerInvariant()), out var field)) continue;
customColumns.Add((i, typeKey, field));
}

int GetIndex(string name) => col.TryGetValue(name, out var idx) ? idx : -1;
string GetValue(string[] row, string name)
{
var idx = GetIndex(name);
if (idx < 0 || idx >= row.Length) return "";
return row[idx];
}

var imported = 0;
for (var r = 1; r < rows.Count; r++)
{
var row = rows[r];
if (row.All(v => string.IsNullOrWhiteSpace(v))) continue;

var typ = GetValue(row, "typ").Trim();
var datumText = GetValue(row, "datum").Trim();
var datum = ParseDateForImport(datumText);
if (datum == default) datum = DateTime.Today;

var zaznam = new TreninkovyZaznam
{
Datum = datum,
Typ = string.IsNullOrWhiteSpace(typ) ? "cviceni" : typ.Trim().ToLowerInvariant()
};
if (!IsBuiltInType(zaznam.Typ) && !customTypeByKey.ContainsKey(zaznam.Typ))
{
zaznam.Typ = "cviceni";
}

zaznam.Poznamka = GetValue(row, "poznamka");
var tagyRaw = GetValue(row, "tagy");
zaznam.Tagy = string.IsNullOrWhiteSpace(tagyRaw) ? "" : NormalizeTags(tagyRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
zaznam.Pocasi = GetValue(row, "pocasi");

zaznam.Cviceni = GetValue(row, "cviceni");
zaznam.Serie = ParseInt(GetValue(row, "serie"));
zaznam.Opakovani = ParseInt(GetValue(row, "opakovani"));
zaznam.DobaMinuty = ParseInt(GetValue(row, "dobaMinuty"));

zaznam.VzdalenostKm = ParseDouble(GetValue(row, "vzdalenostKm"));
zaznam.Tempo = GetValue(row, "tempo");
zaznam.PrevyseniM = ParseInt(GetValue(row, "prevyseniM"));
zaznam.Tep = ParseInt(GetValue(row, "tep"));

zaznam.VelikostBazenuM = ParseInt(GetValue(row, "velikostBazenuM"));
zaznam.VzdalenostM = ParseInt(GetValue(row, "vzdalenostM"));
zaznam.DobaPlavaniMin = ParseInt(GetValue(row, "dobaPlavaniMin"));

var customValues = new Dictionary<int, string>();
if (customColumns.Count > 0 && customTypeByKey.ContainsKey(zaznam.Typ))
{
foreach (var colMap in customColumns)
{
if (!string.Equals(colMap.TypeKey, zaznam.Typ, StringComparison.OrdinalIgnoreCase)) continue;
if (colMap.Index < 0 || colMap.Index >= row.Length) continue;
var raw = row[colMap.Index];
if (string.IsNullOrWhiteSpace(raw)) continue;
var f = colMap.Field;
if (string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase))
{
var val = ParseDouble(raw);
val = ClampDouble(val, f.MinValue, f.MaxValue);
customValues[f.Id] = val.ToString("0.##", CultureInfo.InvariantCulture);
}
else if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
var lowered = raw.Trim().ToLowerInvariant();
if (lowered == "1" || lowered == "true" || lowered == "ano" || lowered == "yes")
customValues[f.Id] = "1";
}
else
{
customValues[f.Id] = raw.Trim();
}
}
}

var newId = DbInsert(zaznam, user.Id);
if (customValues.Count > 0) DbReplaceCustomValues(newId, customValues);
imported++;
}

var okBody = $"<h2>Import</h2><p>Importováno záznamů: <b>{imported}</b></p>";
okBody += "<p><a class=\"btn-secondary\" href=\"/zaznamy\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zobrazit záznamy</a></p>";
return Results.Content(PageLayout("Import", okBody, user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/admin/users", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
if (!user.IsAdmin) return Results.Redirect("/");

var users = DbGetAllUsers();
var sb = new StringBuilder();
sb.Append("<h2>Správa účtů</h2>");
sb.Append($"<p style=\"color:#64748b; margin:0 0 0.75rem\">Celkem: <b>{users.Count}</b></p>");
sb.Append("<div class=\"card\"><table><thead><tr><th>Uživatel</th><th>Role</th><th>Vytvořeno</th></tr></thead><tbody>");
foreach (var u in users)
{
var role = u.IsAdmin ? "Admin" : "Uživatel";
var created = string.IsNullOrWhiteSpace(u.CreatedAt) ? "" : H(u.CreatedAt);
sb.Append("<tr>");
sb.Append($"<td><a href=\"/zaznamy?user={u.Id}\" style=\"color:#2563eb; text-decoration:none\">{H(u.Username)}</a></td>");
sb.Append($"<td>{role}</td>");
sb.Append($"<td>{created}</td>");
sb.Append("</tr>");
}
sb.Append("</tbody></table></div>");

return Results.Content(PageLayout("Správa účtů", sb.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var body = new StringBuilder();
body.Append("""
<h2>Rozcestník</h2>
<p style="color:#475569; margin-top:0">Vyberte, kam chcete pokračovat.</p>
<div class="menu-grid">
<a class="menu-card menu-new" href="/novy">
<span class="menu-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M4 20h16"></path>
<path d="M6 16l5-5 2 2 5-5"></path>
<path d="M15 6h4v4"></path>
</svg>
</span>
<span class="menu-title">Nový záznam</span>
<span class="menu-desc">Založ nový trénink a ulož detaily.</span>
</a>
<a class="menu-card menu-list" href="/zaznamy">
<span class="menu-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M7 7h10"></path>
<path d="M7 12h10"></path>
<path d="M7 17h6"></path>
<circle cx="4" cy="7" r="1.5"></circle>
<circle cx="4" cy="12" r="1.5"></circle>
<circle cx="4" cy="17" r="1.5"></circle>
</svg>
</span>
<span class="menu-title">Záznamy</span>
<span class="menu-desc">Projdi historii, filtruj a upravuj.</span>
</a>
<a class="menu-card menu-stats" href="/statistiky">
<span class="menu-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M4 19h16"></path>
<path d="M7 19V9"></path>
<path d="M12 19V5"></path>
<path d="M17 19v-7"></path>
</svg>
</span>
<span class="menu-title">Statistiky</span>
<span class="menu-desc">Rychlý přehled výkonu a trendu.</span>
</a>
<a class="menu-card menu-types" href="/typy">
<span class="menu-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M12 4v16"></path>
<path d="M4 12h16"></path>
</svg>
</span>
<span class="menu-title">Vytvořit nový druh cvičení</span>
<span class="menu-desc">Vytvoř vlastní typy cvičení a atributy.</span>
</a>
</div>
""");
var publicRecords = DbGetPublicLatest(6);
if (publicRecords.Count > 0)
{
var allUsers = DbGetAllUsers();
var userNameById = allUsers.ToDictionary(u => u.Id, u => u.Username);
var publicTypeMapAll = new Dictionary<(int, string), string>();
foreach (var ct in DbGetAllCustomTypes())
{
publicTypeMapAll[(ct.UserId, ct.Key)] = ct.Name;
}
var emptyTypeMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
body.Append("<h3 style=\"margin-top:1.5rem\">Veřejné aktivity</h3>");
body.Append("<div class=\"card\"><table><thead><tr><th>Datum</th><th>Uživatel</th><th>Typ</th><th>Poznámka</th></tr></thead><tbody>");
foreach (var z in publicRecords)
{
var username = userNameById.TryGetValue(z.UserId, out var u) ? u : "uživatel";
var typText = GetTypeLabel(z, emptyTypeMap, publicTypeMapAll);
var note = string.IsNullOrWhiteSpace(z.Poznamka) ? "" : H(z.Poznamka);
body.Append("<tr>");
body.Append($"<td>{z.Datum:dd.MM.yyyy}</td>");
body.Append($"<td>{H(username)}</td>");
body.Append($"<td>{H(typText)}</td>");
body.Append($"<td>{note}</td>");
body.Append("</tr>");
}
body.Append("</tbody></table></div>");
}

return Results.Content(PageLayout("Rozcestník", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/novy", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var customTypes = DbGetCustomTypes(user.Id);
var customFields = DbGetCustomFieldsForTypes(customTypes.Select(t => t.Id).ToList());
var customFieldsByType = customFields.GroupBy(f => f.TypeId).ToDictionary(g => g.Key, g => g.ToList());
var body = new StringBuilder();
body.Append("""
<h2>Nový záznam</h2>
<form method="post" action="/trenink" enctype="multipart/form-data">
<div class="grid">
<div class="field">
<label for="datum">Datum</label>
<input id="datum" name="datum" type="date" required />
</div>
<div class="field">
<label for="typ">Typ</label>
""");
body.Append("<select id=\"typ\" name=\"typ\">");
foreach (var t in BuiltInTypes)
{
var selected = t.Key == "cviceni" ? " selected" : "";
body.Append($"<option value=\"{H(t.Key)}\"{selected}>{H(t.Label)}</option>");
}
foreach (var ct in customTypes)
{
body.Append($"<option value=\"{H(ct.Key)}\">{H(ct.Name)}</option>");
}
body.Append("</select>");
body.Append("""
</div>
</div>

<div id="sekce-beh" class="typ-section" data-typ="beh" style="display:none">
<h3>Běh</h3>
<div class="grid">
<div class="field">
<label for="beh-vzdalenost">Vzdálenost (km)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-vzdalenost" name="beh_vzd_int">
""");
for (var i = 0; i <= 500; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
<span class="inline-sep">.</span>
<div class="inline-part">
<select name="beh_vzd_dec">
""");
for (var i = 0; i <= 9; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
<span class="inline-suffix">km</span>
</div>
</div>
<div class="field">
<label for="beh-tempo">Tempo (HH:MM:SS)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-tempo" name="beh_tempo_h">
""");
for (var i = 0; i <= 60; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">h</span>
</div>
<div class="inline-part">
<select name="beh_tempo_m">
""");
for (var i = 0; i <= 59; i++)
{
var sel = i == 6 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">m</span>
</div>
<div class="inline-part">
<select name="beh_tempo_s">
""");
for (var i = 0; i <= 59; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">s</span>
</div>
</div>
</div>
<div class="field">
<label for="beh-prevyseni">Převýšení (m)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-prevyseni" name="beh_prev_k">
""");
for (var i = 0; i <= 100; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">tis.</span>
</div>
<div class="inline-part">
<select name="beh_prev_r">
""");
for (var i = 0; i <= 999; i++)
{
var sel = i == 0 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:000}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">m</span>
</div>
</div>
</div>
<div class="field">
<label for="beh-tep">Tep (průměr)</label>
<select id="beh-tep" name="beh_tep">
""");
for (var i = 0; i <= 210; i++)
{
var sel = i == 130 ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
</div>
</div>

<div id="sekce-cviceni" class="typ-section" data-typ="cviceni">
<h3>Cvičení</h3>
<div class="grid">
<div class="field">
<label for="cviceni">Název cvičení</label>
<input id="cviceni" type="text" name="cviceni" list="cviky" />
<datalist id="cviky">
<option value="Dřepy"></option>
<option value="Mrtvý tah"></option>
<option value="Bench press"></option>
<option value="Tlaky nad hlavu"></option>
<option value="Přítahy na hrazdě"></option>
<option value="Kliky"></option>
<option value="Výpady"></option>
<option value="Plank"></option>
<option value="Core"></option>
</datalist>
</div>
<div class="field">
<label for="serie">Počet sérií</label>
<input id="serie" type="number" name="serie" min="0" />
</div>
<div class="field">
<label for="opak">Počet opakování</label>
<input id="opak" type="number" name="opak" min="0" />
</div>
<div class="field">
<label for="doba">Doba cvičení (min)</label>
<input id="doba" type="number" name="doba" min="0" />
</div>
</div>
</div>

<div id="sekce-plavani" class="typ-section" data-typ="plavani" style="display:none">
<h3>Plavání</h3>
<div class="grid">
<div class="field">
<label for="plav-bazen">Velikost bazénu (m)</label>
<input id="plav-bazen" type="number" min="0" name="plav_bazen" />
</div>
<div class="field">
<label for="plav-vzdalenost">Vzdálenost (m)</label>
<input id="plav-vzdalenost" type="number" min="0" name="plav_vzdalenost" />
</div>
<div class="field">
<label for="plav-doba">Doba plavání (min)</label>
<input id="plav-doba" type="number" min="0" name="plav_doba" />
</div>
</div>
</div>

<div id="sekce-kolo" class="typ-section" data-typ="kolo" style="display:none">
<h3>Kolo</h3>
<div class="grid">
<div class="field">
<label for="kolo-vzdalenost">Vzdálenost (km)</label>
<input id="kolo-vzdalenost" type="number" step="0.01" min="0" name="kolo_vzdalenost" />
</div>
<div class="field">
<label for="kolo-doba">Doba (min)</label>
<input id="kolo-doba" type="number" min="0" name="kolo_doba" />
</div>
<div class="field">
<label for="kolo-prevyseni">Převýšení (m)</label>
<input id="kolo-prevyseni" type="number" min="0" name="kolo_prevyseni" />
</div>
<div class="field">
<label for="kolo-tep">Tep (průměr)</label>
<input id="kolo-tep" type="number" min="0" name="kolo_tep" />
</div>
</div>
</div>

<div id="sekce-turistika" class="typ-section" data-typ="turistika" style="display:none">
<h3>Turistika</h3>
<div class="grid">
<div class="field">
<label for="tur-vzdalenost">Vzdálenost (km)</label>
<input id="tur-vzdalenost" type="number" step="0.01" min="0" name="tur_vzdalenost" />
</div>
<div class="field">
<label for="tur-doba">Doba (min)</label>
<input id="tur-doba" type="number" min="0" name="tur_doba" />
</div>
<div class="field">
<label for="tur-prevyseni">Převýšení (m)</label>
<input id="tur-prevyseni" type="number" min="0" name="tur_prevyseni" />
</div>
<div class="field">
<label for="tur-tep">Tep (průměr)</label>
<input id="tur-tep" type="number" min="0" name="tur_tep" />
</div>
</div>
</div>
""");

foreach (var ct in customTypes)
{
body.Append($"<div class=\"typ-section\" data-typ=\"{H(ct.Key)}\" style=\"display:none\">");
body.Append($"<h3>{H(ct.Name)}</h3>");
body.Append("<div class=\"grid\">");
if (customFieldsByType.TryGetValue(ct.Id, out var fl))
{
foreach (var f in fl)
{
var inputName = $"custom_{f.Id}";
var unit = string.IsNullOrWhiteSpace(f.Unit) ? "" : $" ({H(f.Unit)})";
if (string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase))
{
var minAttr = f.MinValue is null ? "" : " min=\"" + H(f.MinValue.Value.ToString("0.##", CultureInfo.InvariantCulture)) + "\"";
var maxAttr = f.MaxValue is null ? "" : " max=\"" + H(f.MaxValue.Value.ToString("0.##", CultureInfo.InvariantCulture)) + "\"";
body.Append($"<div class=\"field\"><label for=\"{H(inputName)}\">{H(f.Label)}{unit}</label><input id=\"{H(inputName)}\" type=\"number\" step=\"0.01\" name=\"{H(inputName)}\"{minAttr}{maxAttr} /></div>");
}
else if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
body.Append($"<div class=\"field\"><label>{H(f.Label)}</label><label style=\"display:flex; gap:0.4rem; align-items:center\"><input type=\"checkbox\" name=\"{H(inputName)}\" value=\"1\" /> ano</label></div>");
}
else
{
body.Append($"<div class=\"field\"><label for=\"{H(inputName)}\">{H(f.Label)}{unit}</label><input id=\"{H(inputName)}\" type=\"text\" name=\"{H(inputName)}\" /></div>");
}
}
}
body.Append("</div></div>");
}

body.Append("""
<div class="field" style="margin-top:1rem">
<label for="poznamka">Poznámka</label>
<textarea id="poznamka" name="poznamka" rows="3" style="width:100%; padding:0.55rem 0.65rem; border: 1px solid var(--border); border-radius: 10px; font-size: 1rem; background: white; resize: vertical"></textarea>
<div class="tag-list" style="margin-top:0.6rem">
<label><input type="checkbox" name="tag" value="intervaly" /> intervaly</label>
<label><input type="checkbox" name="tag" value="závod" /> závod</label>
<label><input type="checkbox" name="tag" value="easy" /> easy</label>
<label><input type="checkbox" name="tag" value="bolest" /> bolest</label>
</div>
</div>
<div class="field" style="margin-top:0.75rem">
<label for="pocasi">Počasí</label>
<input id="pocasi" type="text" name="pocasi" placeholder="např. slunečno, 18°C, vítr" />
</div>
<div class="field" style="margin-top:0.75rem">
<label>Viditelnost</label>
<label style="display:flex; gap:0.4rem; align-items:center">
<input type="checkbox" name="is_public" value="1" style="width:auto; margin:0" /> veřejný záznam (zobrazí se na rozcestníku)
</label>
</div>
<div class="field" style="margin-top:0.75rem">
<label for="fotky">Soubory</label>
<input id="fotky" class="file-input" type="file" name="fotky" multiple />
<label class="btn-secondary file-label" for="fotky">
<span class="icon-inline" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M12 3v12"></path>
<path d="M8 11l4 4 4-4"></path>
<path d="M4 21h16"></path>
</svg>
</span>
Zvolit soubor
</label>
<div style="font-size:0.85rem; color: var(--muted); margin-top:0.35rem">Můžete přidat fotky i jiné soubory.</div>
</div>
<div class="actions">
<button type="submit">Uložit</button>
</div>
</form>

<script>
(function(){
function syncSections(){
var typ = document.getElementById('typ').value;
document.querySelectorAll('.typ-section').forEach(function(sec){
sec.style.display = (sec.getAttribute('data-typ')===typ) ? '' : 'none';
});
}
document.getElementById('typ').addEventListener('change', syncSections);
syncSections();
})();
</script>
""");

return Results.Content(PageLayout("Tréninkový deník", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapPost("/trenink", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();

var datumText = form["datum"].ToString();
var typ = (form["typ"].ToString() ?? "").Trim();

DateTime.TryParse(datumText, CultureInfo.InvariantCulture, DateTimeStyles.None, out var datum);
if (datum == default) datum = DateTime.Today;

var zaznam = new TreninkovyZaznam
{
// Id si řeší DB (AUTOINCREMENT)
Datum = datum,
Typ = string.IsNullOrWhiteSpace(typ) ? "cviceni" : typ
};

zaznam.Poznamka = form["poznamka"].ToString();
zaznam.Tagy = NormalizeTags(form["tag"].ToArray());
zaznam.Pocasi = form["pocasi"].ToString();
zaznam.IsPublic = form.ContainsKey("is_public");

var customValues = new Dictionary<int, string>();
CustomType? customType = null;
if (!IsBuiltInType(zaznam.Typ))
{
customType = DbGetCustomTypeByKey(user.Id, zaznam.Typ);
if (customType is null)
{
zaznam.Typ = "cviceni";
}
}

if (customType is not null)
{
var fields = DbGetCustomFieldsByTypeId(customType.Id);
foreach (var f in fields)
{
var key = $"custom_{f.Id}";
if (string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase))
{
var raw = form[key].ToString();
if (string.IsNullOrWhiteSpace(raw)) continue;
var val = ParseDouble(raw);
val = ClampDouble(val, f.MinValue, f.MaxValue);
customValues[f.Id] = val.ToString("0.##", CultureInfo.InvariantCulture);
}
else if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
if (form.ContainsKey(key)) customValues[f.Id] = "1";
}
else
{
var raw = form[key].ToString();
if (!string.IsNullOrWhiteSpace(raw)) customValues[f.Id] = raw.Trim();
}
}
}
else if (zaznam.Typ == "beh")
{
zaznam.VzdalenostKm = BuildDistanceFromForm(form, "beh");
zaznam.Tempo = BuildTempoFromForm(form, "beh");
zaznam.PrevyseniM = BuildPrevyseniFromForm(form, "beh");
zaznam.Tep = ClampInt(ParseInt(form["beh_tep"].ToString()), 0, 210);
}
else if (zaznam.Typ == "kolo")
{
zaznam.VzdalenostKm = ParseDouble(form["kolo_vzdalenost"].ToString());
zaznam.DobaMinuty = ParseInt(form["kolo_doba"].ToString());
zaznam.PrevyseniM = ParseInt(form["kolo_prevyseni"].ToString());
zaznam.Tep = ParseInt(form["kolo_tep"].ToString());
}
else if (zaznam.Typ == "turistika")
{
zaznam.VzdalenostKm = ParseDouble(form["tur_vzdalenost"].ToString());
zaznam.DobaMinuty = ParseInt(form["tur_doba"].ToString());
zaznam.PrevyseniM = ParseInt(form["tur_prevyseni"].ToString());
zaznam.Tep = ParseInt(form["tur_tep"].ToString());
}
else if (zaznam.Typ == "plavani")
{
zaznam.VelikostBazenuM = ParseInt(form["plav_bazen"].ToString());
zaznam.VzdalenostM = ParseInt(form["plav_vzdalenost"].ToString());
zaznam.DobaPlavaniMin = ParseInt(form["plav_doba"].ToString());
}
else
{
zaznam.Typ = "cviceni";
zaznam.Cviceni = form["cviceni"].ToString();
zaznam.Serie = ParseInt(form["serie"].ToString());
zaznam.Opakovani = ParseInt(form["opak"].ToString());
zaznam.DobaMinuty = ParseInt(form["doba"].ToString());
}

var newId = DbInsert(zaznam, user.Id);
DbReplaceCustomValues(newId, customValues);
await SavePhotosAsync(form.Files, newId, user.Id);
return Results.Redirect("/zaznamy");
});

app.MapPost("/smazat", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (int.TryParse(form["id"].ToString(), out var id))
{
DbDelete(id, user.Id, user.IsAdmin);
}
return Results.Redirect("/zaznamy");
});

app.MapGet("/edit", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
if (!int.TryParse(context.Request.Query["id"].ToString(), out var id))
return Results.Redirect("/zaznamy");

var z = DbGetById(id, user.IsAdmin ? null : user.Id);
if (z is null)
return Results.Content(PageLayout("Editace", "<p>Záznam nenalezen.</p>", user.Username, user.IsAdmin), "text/html; charset=utf-8");

static string ValD(double v) => v == 0 ? "" : v.ToString("0.##", CultureInfo.InvariantCulture);
static string ValI(int v) => v == 0 ? "" : v.ToString(CultureInfo.InvariantCulture);
var ownerUserId = user.IsAdmin ? z.UserId : user.Id;
var customTypes = DbGetCustomTypes(ownerUserId);
var customFields = DbGetCustomFieldsForTypes(customTypes.Select(t => t.Id).ToList());
var customFieldsByType = customFields.GroupBy(f => f.TypeId).ToDictionary(g => g.Key, g => g.ToList());
var customValues = DbGetCustomValuesByRecord(z.Id);
SplitDistance(z.VzdalenostKm, out var behVzdInt, out var behVzdDec);
var (behTempoH, behTempoM, behTempoS) = ParseTempoParts(z.Tempo);
var behPrevVal = ClampInt(z.PrevyseniM, 0, 100000);
var behPrevK = behPrevVal / 1000;
var behPrevR = behPrevVal % 1000;
var behTep = ClampInt(z.Tep, 0, 210);

var body = new StringBuilder();
body.Append($"<h2>Editace záznamu</h2><p style=\"color:#64748b;margin-top:-0.25rem\">ID: {z.Id}</p>");

body.Append($"""
<form method="post" action="/edit">
<input type="hidden" name="id" value="{z.Id}" />
<div class="grid">
<div class="field">
<label for="datum">Datum</label>
<input id="datum" name="datum" type="date" required value="{H(DateToIso(z.Datum))}" />
</div>
<div class="field">
<label for="typ">Typ</label>
""");
body.Append("<select id=\"typ\" name=\"typ\">");
foreach (var t in BuiltInTypes)
{
body.Append($"<option value=\"{H(t.Key)}\">{H(t.Label)}</option>");
}
foreach (var ct in customTypes)
{
body.Append($"<option value=\"{H(ct.Key)}\">{H(ct.Name)}</option>");
}
body.Append("</select>");
body.Append($"""
</div>
</div>
<div id="sekce-beh" class="typ-section" data-typ="beh" style="display:none">
<h3>Běh</h3>
<div class="grid">
<div class="field">
<label for="beh-vzdalenost">Vzdálenost (km)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-vzdalenost" name="beh_vzd_int">
""");
for (var i = 0; i <= 500; i++)
{
var sel = i == behVzdInt ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
<span class="inline-sep">.</span>
<div class="inline-part">
<select name="beh_vzd_dec">
""");
for (var i = 0; i <= 9; i++)
{
var sel = i == behVzdDec ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
<span class="inline-suffix">km</span>
</div>
</div>
<div class="field">
<label for="beh-tempo">Tempo (HH:MM:SS)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-tempo" name="beh_tempo_h">
""");
for (var i = 0; i <= 60; i++)
{
var sel = i == behTempoH ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">h</span>
</div>
<div class="inline-part">
<select name="beh_tempo_m">
""");
for (var i = 0; i <= 59; i++)
{
var sel = i == behTempoM ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">m</span>
</div>
<div class="inline-part">
<select name="beh_tempo_s">
""");
for (var i = 0; i <= 59; i++)
{
var sel = i == behTempoS ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:00}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">s</span>
</div>
</div>
</div>
<div class="field">
<label for="beh-prevyseni">Převýšení (m)</label>
<div class="inline-selects">
<div class="inline-part">
<select id="beh-prevyseni" name="beh_prev_k">
""");
for (var i = 0; i <= 100; i++)
{
var sel = i == behPrevK ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">tis.</span>
</div>
<div class="inline-part">
<select name="beh_prev_r">
""");
for (var i = 0; i <= 999; i++)
{
var sel = i == behPrevR ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i:000}</option>");
}
body.Append("""
</select>
<span class="inline-suffix">m</span>
</div>
</div>
</div>
<div class="field">
<label for="beh-tep">Tep (průměr)</label>
<select id="beh-tep" name="beh_tep">
""");
for (var i = 0; i <= 210; i++)
{
var sel = i == behTep ? " selected" : "";
body.Append($"<option value=\"{i}\"{sel}>{i}</option>");
}
body.Append("""
</select>
</div>
</div>
</div>
""");
body.Append($"""
<div id="sekce-cviceni" class="typ-section" data-typ="cviceni" style="display:none">
<h3>Cvičení</h3>
<div class="grid">
<div class="field">
<label for="cviceni">Název cvičení</label>
<input id="cviceni" type="text" name="cviceni" list="cviky" value="{H(z.Cviceni)}" />
<datalist id="cviky">
<option value="Dřepy"></option>
<option value="Mrtvý tah"></option>
<option value="Bench press"></option>
<option value="Tlaky nad hlavu"></option>
<option value="Přítahy na hrazdě"></option>
<option value="Kliky"></option>
<option value="Výpady"></option>
<option value="Plank"></option>
<option value="Core"></option>
</datalist>
</div>
<div class="field">
<label for="serie">Počet sérií</label>
<input id="serie" type="number" name="serie" min="0" value="{H(ValI(z.Serie))}" />
</div>
<div class="field">
<label for="opak">Počet opakování</label>
<input id="opak" type="number" name="opak" min="0" value="{H(ValI(z.Opakovani))}" />
</div>
<div class="field">
<label for="doba">Doba cvičení (min)</label>
<input id="doba" type="number" name="doba" min="0" value="{H(ValI(z.DobaMinuty))}" />
</div>
</div>
</div>
<div id="sekce-kolo" class="typ-section" data-typ="kolo" style="display:none">
<h3>Kolo</h3>
<div class="grid">
<div class="field">
<label for="kolo-vzdalenost">Vzdálenost (km)</label>
<input id="kolo-vzdalenost" type="number" step="0.01" min="0" name="kolo_vzdalenost" value="{H(ValD(z.VzdalenostKm))}" />
</div>
<div class="field">
<label for="kolo-doba">Doba (min)</label>
<input id="kolo-doba" type="number" min="0" name="kolo_doba" value="{H(ValI(z.DobaMinuty))}" />
</div>
<div class="field">
<label for="kolo-prevyseni">Převýšení (m)</label>
<input id="kolo-prevyseni" type="number" min="0" name="kolo_prevyseni" value="{H(ValI(z.PrevyseniM))}" />
</div>
<div class="field">
<label for="kolo-tep">Tep (průměr)</label>
<input id="kolo-tep" type="number" min="0" name="kolo_tep" value="{H(ValI(z.Tep))}" />
</div>
</div>
</div>
<div id="sekce-turistika" class="typ-section" data-typ="turistika" style="display:none">
<h3>Turistika</h3>
<div class="grid">
<div class="field">
<label for="tur-vzdalenost">Vzdálenost (km)</label>
<input id="tur-vzdalenost" type="number" step="0.01" min="0" name="tur_vzdalenost" value="{H(ValD(z.VzdalenostKm))}" />
</div>
<div class="field">
<label for="tur-doba">Doba (min)</label>
<input id="tur-doba" type="number" min="0" name="tur_doba" value="{H(ValI(z.DobaMinuty))}" />
</div>
<div class="field">
<label for="tur-prevyseni">Převýšení (m)</label>
<input id="tur-prevyseni" type="number" min="0" name="tur_prevyseni" value="{H(ValI(z.PrevyseniM))}" />
</div>
<div class="field">
<label for="tur-tep">Tep (průměr)</label>
<input id="tur-tep" type="number" min="0" name="tur_tep" value="{H(ValI(z.Tep))}" />
</div>
</div>
</div>
<div id="sekce-plavani" class="typ-section" data-typ="plavani" style="display:none">
<h3>Plavání</h3>
<div class="grid">
<div class="field">
<label for="plav-bazen">Velikost bazénu (m)</label>
<input id="plav-bazen" type="number" min="0" name="plav_bazen" value="{H(ValI(z.VelikostBazenuM))}" />
</div>
<div class="field">
<label for="plav-vzdalenost">Vzdálenost (m)</label>
<input id="plav-vzdalenost" type="number" min="0" name="plav_vzdalenost" value="{H(ValI(z.VzdalenostM))}" />
</div>
<div class="field">
<label for="plav-doba">Doba plavání (min)</label>
<input id="plav-doba" type="number" min="0" name="plav_doba" value="{H(ValI(z.DobaPlavaniMin))}" />
</div>
</div>
</div>
""");

foreach (var ct in customTypes)
{
body.Append($"<div class=\"typ-section\" data-typ=\"{H(ct.Key)}\" style=\"display:none\">");
body.Append($"<h3>{H(ct.Name)}</h3>");
body.Append("<div class=\"grid\">");
if (customFieldsByType.TryGetValue(ct.Id, out var fl))
{
foreach (var f in fl)
{
var inputName = $"custom_{f.Id}";
var unit = string.IsNullOrWhiteSpace(f.Unit) ? "" : $" ({H(f.Unit)})";
customValues.TryGetValue(f.Id, out var value);
if (string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase))
{
var minAttr = f.MinValue is null ? "" : " min=\"" + H(f.MinValue.Value.ToString("0.##", CultureInfo.InvariantCulture)) + "\"";
var maxAttr = f.MaxValue is null ? "" : " max=\"" + H(f.MaxValue.Value.ToString("0.##", CultureInfo.InvariantCulture)) + "\"";
var valAttr = string.IsNullOrWhiteSpace(value) ? "" : $" value=\"{H(value)}\"";
body.Append($"<div class=\"field\"><label for=\"{H(inputName)}\">{H(f.Label)}{unit}</label><input id=\"{H(inputName)}\" type=\"number\" step=\"0.01\" name=\"{H(inputName)}\"{minAttr}{maxAttr}{valAttr} /></div>");
}
else if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
var checkedAttr = value == "1" || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ? " checked" : "";
body.Append($"<div class=\"field\"><label>{H(f.Label)}</label><label style=\"display:flex; gap:0.4rem; align-items:center\"><input type=\"checkbox\" name=\"{H(inputName)}\" value=\"1\"{checkedAttr} /> ano</label></div>");
}
else
{
var valAttr = string.IsNullOrWhiteSpace(value) ? "" : $" value=\"{H(value)}\"";
body.Append($"<div class=\"field\"><label for=\"{H(inputName)}\">{H(f.Label)}{unit}</label><input id=\"{H(inputName)}\" type=\"text\" name=\"{H(inputName)}\"{valAttr} /></div>");
}
}
}
body.Append("</div></div>");
}

body.Append($"""
<div class="field" style="margin-top:1rem">
<label for="poznamka">Poznámka</label>
<textarea id="poznamka" name="poznamka" rows="3" style="width:100%; padding:0.55rem 0.65rem; border: 1px solid var(--border); border-radius: 10px; font-size: 1rem; background: white; resize: vertical">{H(z.Poznamka)}</textarea>
<div class="tag-list" style="margin-top:0.6rem">
<label><input type="checkbox" name="tag" value="intervaly" {(TagSet(z.Tagy).Contains("intervaly") ? "checked" : "")} /> intervaly</label>
<label><input type="checkbox" name="tag" value="závod" {(TagSet(z.Tagy).Contains("závod") ? "checked" : "")} /> závod</label>
<label><input type="checkbox" name="tag" value="easy" {(TagSet(z.Tagy).Contains("easy") ? "checked" : "")} /> easy</label>
<label><input type="checkbox" name="tag" value="bolest" {(TagSet(z.Tagy).Contains("bolest") ? "checked" : "")} /> bolest</label>
</div>
</div>
<div class="field" style="margin-top:0.75rem">
<label for="pocasi">Počasí</label>
<input id="pocasi" type="text" name="pocasi" value="{H(z.Pocasi)}" />
</div>
<div class="field" style="margin-top:0.75rem">
<label>Viditelnost</label>
<label style="display:flex; gap:0.4rem; align-items:center">
<input type="checkbox" name="is_public" value="1" {(z.IsPublic ? "checked" : "")} style="width:auto; margin:0" /> veřejný záznam (zobrazí se na rozcestníku)
</label>
</div>
<div class="actions" style="display:flex; gap:0.5rem; flex-wrap:wrap">
<button type="submit">Uložit změny</button>
<a class="btn-secondary" href="/zaznamy" style="display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none; font-weight:800">Zpět</a>
</div>
</form>
""");

body.Append("<script>(function(){");
body.Append("var typEl=document.getElementById(\"typ\");");
body.Append("typEl.value=\"");
body.Append(H(z.Typ));
body.Append("\";");
body.Append("function syncSections(){var typ=typEl.value;document.querySelectorAll('.typ-section').forEach(function(sec){sec.style.display=(sec.getAttribute('data-typ')===typ)?'':'';});}");
body.Append("typEl.addEventListener(\"change\",syncSections);syncSections();");
body.Append("})();</script>");

return Results.Content(PageLayout("Editace", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapPost("/edit", async (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var form = await context.Request.ReadFormAsync();
if (!int.TryParse(form["id"].ToString(), out var id))
return Results.Redirect("/zaznamy");
var existing = DbGetById(id, user.IsAdmin ? null : user.Id);
if (existing is null) return Results.Redirect("/zaznamy");

var datumText = form["datum"].ToString();
var typ = (form["typ"].ToString() ?? "").Trim();
DateTime.TryParse(datumText, CultureInfo.InvariantCulture, DateTimeStyles.None, out var datum);
if (datum == default) datum = DateTime.Today;

var zaznam = new TreninkovyZaznam
{
Id = id,
Datum = datum,
Typ = string.IsNullOrWhiteSpace(typ) ? "cviceni" : typ
};

zaznam.Poznamka = form["poznamka"].ToString();
zaznam.Tagy = NormalizeTags(form["tag"].ToArray());
zaznam.Pocasi = form["pocasi"].ToString();

var ownerUserId = user.IsAdmin ? existing.UserId : user.Id;
var customValues = new Dictionary<int, string>();
CustomType? customType = null;
if (!IsBuiltInType(zaznam.Typ))
{
customType = DbGetCustomTypeByKey(ownerUserId, zaznam.Typ);
if (customType is null)
{
zaznam.Typ = "cviceni";
}
}

if (customType is not null)
{
var fields = DbGetCustomFieldsByTypeId(customType.Id);
foreach (var f in fields)
{
var key = $"custom_{f.Id}";
if (string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase))
{
var raw = form[key].ToString();
if (string.IsNullOrWhiteSpace(raw)) continue;
var val = ParseDouble(raw);
val = ClampDouble(val, f.MinValue, f.MaxValue);
customValues[f.Id] = val.ToString("0.##", CultureInfo.InvariantCulture);
}
else if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
if (form.ContainsKey(key)) customValues[f.Id] = "1";
}
else
{
var raw = form[key].ToString();
if (!string.IsNullOrWhiteSpace(raw)) customValues[f.Id] = raw.Trim();
}
}
}
else if (zaznam.Typ == "beh")
{
zaznam.VzdalenostKm = BuildDistanceFromForm(form, "beh");
zaznam.Tempo = BuildTempoFromForm(form, "beh");
zaznam.PrevyseniM = BuildPrevyseniFromForm(form, "beh");
zaznam.Tep = ClampInt(ParseInt(form["beh_tep"].ToString()), 0, 210);
}
else if (zaznam.Typ == "kolo")
{
zaznam.VzdalenostKm = ParseDouble(form["kolo_vzdalenost"].ToString());
zaznam.DobaMinuty = ParseInt(form["kolo_doba"].ToString());
zaznam.PrevyseniM = ParseInt(form["kolo_prevyseni"].ToString());
zaznam.Tep = ParseInt(form["kolo_tep"].ToString());
}
else if (zaznam.Typ == "turistika")
{
zaznam.VzdalenostKm = ParseDouble(form["tur_vzdalenost"].ToString());
zaznam.DobaMinuty = ParseInt(form["tur_doba"].ToString());
zaznam.PrevyseniM = ParseInt(form["tur_prevyseni"].ToString());
zaznam.Tep = ParseInt(form["tur_tep"].ToString());
}
else if (zaznam.Typ == "plavani")
{
zaznam.VelikostBazenuM = ParseInt(form["plav_bazen"].ToString());
zaznam.VzdalenostM = ParseInt(form["plav_vzdalenost"].ToString());
zaznam.DobaPlavaniMin = ParseInt(form["plav_doba"].ToString());
}
else
{
zaznam.Typ = "cviceni";
zaznam.Cviceni = form["cviceni"].ToString();
zaznam.Serie = ParseInt(form["serie"].ToString());
zaznam.Opakovani = ParseInt(form["opak"].ToString());
zaznam.DobaMinuty = ParseInt(form["doba"].ToString());
}

DbUpdate(zaznam, user.Id, user.IsAdmin);
DbReplaceCustomValues(zaznam.Id, customValues);
return Results.Redirect("/zaznamy");
});

app.MapGet("/zaznamy", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var request = context.Request;
static DateTime? TryParseDate(string? s)
{
var t = (s ?? "").Trim();
if (string.IsNullOrWhiteSpace(t)) return null;
if (DateTime.TryParseExact(t, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var iso)) return iso.Date;
if (DateTime.TryParse(t, CultureInfo.CurrentCulture, DateTimeStyles.None, out var any)) return any.Date;
if (DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.None, out any)) return any.Date;
return null;
}

var qsFrom = request.Query["from"].ToString();
var qsTo = request.Query["to"].ToString();
var qsTyp = (request.Query["typ"].ToString() ?? "").Trim();
var qsQ = request.Query["q"].ToString();
var selTags = request.Query["tag"].ToArray().Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList();
var last30 = request.Query.ContainsKey("last30");
var last7 = request.Query.ContainsKey("last7");
var last90 = request.Query.ContainsKey("last90");
var qsUser = request.Query["user"].ToString();

User? targetUser = null;
int? adminUserId = null;
if (user.IsAdmin && int.TryParse(qsUser, out var uid))
{
targetUser = DbGetUserById(uid);
if (targetUser is not null) adminUserId = uid;
}

DateTime? from = TryParseDate(qsFrom);
DateTime? to = TryParseDate(qsTo);

if (last7)
{
to = DateTime.Today;
from = DateTime.Today.AddDays(-7);
}
else if (last30)
{
to = DateTime.Today;
from = DateTime.Today.AddDays(-30);
}
else if (last90)
{
to = DateTime.Today;
from = DateTime.Today.AddDays(-90);
}

if (string.IsNullOrWhiteSpace(qsTyp)) qsTyp = "all";

var userFilterId = user.IsAdmin ? adminUserId : user.Id;
var zaznamy = DbQuery(userFilterId, from, to, qsTyp, qsQ, selTags.Count == 0 ? null : selTags);
var filterCustomTypes = (user.IsAdmin && targetUser is null) ? new List<CustomType>() : DbGetCustomTypes(user.IsAdmin && targetUser is not null ? targetUser.Id : user.Id);
var customTypeMap = filterCustomTypes.ToDictionary(t => t.Key, t => t.Name, StringComparer.OrdinalIgnoreCase);
var customTypeMapAll = new Dictionary<(int, string), string>();
if (user.IsAdmin && targetUser is null)
{
foreach (var ct in DbGetAllCustomTypes())
{
customTypeMapAll[(ct.UserId, ct.Key)] = ct.Name;
}
}
var customTypesForDetails = (user.IsAdmin && targetUser is null) ? DbGetAllCustomTypes() : filterCustomTypes;
var customFieldsForDetails = DbGetCustomFieldsForTypes(customTypesForDetails.Select(t => t.Id).ToList());
var customFieldsByTypeId = customFieldsForDetails.GroupBy(f => f.TypeId).ToDictionary(g => g.Key, g => g.ToList());
var customTypeIdByKey = filterCustomTypes.ToDictionary(t => t.Key, t => t.Id, StringComparer.OrdinalIgnoreCase);
var customTypeIdByUserKey = new Dictionary<(int, string), int>();
if (user.IsAdmin && targetUser is null)
{
foreach (var ct in customTypesForDetails)
{
customTypeIdByUserKey[(ct.UserId, ct.Key)] = ct.Id;
}
}
var customValuesByRecord = DbGetCustomValuesForRecords(zaznamy.Select(z => z.Id).ToList());

var sb = new StringBuilder();
sb.Append("<h2>Uložené záznamy</h2>");
if (user.IsAdmin && targetUser is not null)
{
sb.Append($"<p style=\"color:#64748b; margin:0 0 0.75rem\">Uživatel: <b>{H(targetUser.Username)}</b> (<a href=\"/zaznamy\" style=\"color:#2563eb; text-decoration:none\">zobrazit všechny</a>)</p>");
var userTypes = DbGetCustomTypes(targetUser.Id);
if (userTypes.Count > 0)
{
var typeList = string.Join(", ", userTypes.Select(t => H(t.Name)));
sb.Append($"<p style=\"color:#64748b; margin:-0.35rem 0 0.75rem\">Vlastní typy: {typeList} (<a href=\"/typy?user={targetUser.Id}\" style=\"color:#2563eb; text-decoration:none\">zobrazit</a>)</p>");
}
}

// Filtry
sb.Append("<div style=\"margin:0.75rem 0 1rem\">\n");
sb.Append("<form method=\"get\" action=\"/zaznamy\" class=\"filters-form\" style=\"display:flex; gap:0.75rem; flex-wrap:wrap; align-items:flex-end\">\n");

sb.Append("<div class=\"field\" style=\"min-width:160px\">\n<label for=\"from\">Od</label>\n");
sb.Append($"<input id=\"from\" name=\"from\" type=\"date\" value=\"{H(from is null ? "" : DateToIso(from.Value))}\" />\n</div>");

sb.Append("<div class=\"field\" style=\"min-width:160px\">\n<label for=\"to\">Do</label>\n");
sb.Append($"<input id=\"to\" name=\"to\" type=\"date\" value=\"{H(to is null ? "" : DateToIso(to.Value))}\" />\n</div>");

sb.Append("<div class=\"field\" style=\"min-width:190px\">\n<label for=\"typ\">Typ</label>\n<select id=\"typ\" name=\"typ\">\n");
sb.Append($"<option value=\"all\" {(qsTyp=="all" ? "selected" : "")}>Vše</option>");
sb.Append($"<option value=\"beh\" {(qsTyp=="beh" ? "selected" : "")}>Běh</option>");
sb.Append($"<option value=\"kolo\" {(qsTyp=="kolo" ? "selected" : "")}>Kolo</option>");
sb.Append($"<option value=\"turistika\" {(qsTyp=="turistika" ? "selected" : "")}>Turistika</option>");
sb.Append($"<option value=\"cviceni\" {(qsTyp=="cviceni" ? "selected" : "")}>Cvičení</option>");
sb.Append($"<option value=\"plavani\" {(qsTyp=="plavani" ? "selected" : "")}>Plavání</option>");
foreach (var ct in filterCustomTypes)
{
var selected = string.Equals(qsTyp, ct.Key, StringComparison.OrdinalIgnoreCase) ? "selected" : "";
sb.Append($"<option value=\"{H(ct.Key)}\" {selected}>{H(ct.Name)}</option>");
}
sb.Append("</select>\n</div>");

sb.Append("<div class=\"field\" style=\"min-width:240px; flex:1\">\n<label for=\"q\">Hledat (poznámka)</label>\n");
sb.Append($"<input id=\"q\" name=\"q\" type=\"text\" placeholder=\"např. intervaly\" value=\"{H(qsQ)}\" />\n</div>");

// Tagy (filtr) – stejný styl jako u nového záznamu
sb.Append("<div class=\"field\" style=\"min-width:320px\">\n<label>Tagy</label>\n");
sb.Append("<div class=\"tag-list\" style=\"margin-top:0.6rem\">\n");

var chkIntervaly = selTags.Any(x => string.Equals(x, "intervaly", StringComparison.OrdinalIgnoreCase)) ? "checked" : "";
var chkZavod = selTags.Any(x => string.Equals(x, "závod", StringComparison.OrdinalIgnoreCase)) ? "checked" : "";
var chkEasy = selTags.Any(x => string.Equals(x, "easy", StringComparison.OrdinalIgnoreCase)) ? "checked" : "";
var chkBolest = selTags.Any(x => string.Equals(x, "bolest", StringComparison.OrdinalIgnoreCase)) ? "checked" : "";

sb.Append($"<label><input type=\"checkbox\" name=\"tag\" value=\"intervaly\" {chkIntervaly} /> intervaly</label>");
sb.Append($"<label><input type=\"checkbox\" name=\"tag\" value=\"závod\" {chkZavod} /> závod</label>");
sb.Append($"<label><input type=\"checkbox\" name=\"tag\" value=\"easy\" {chkEasy} /> easy</label>");
sb.Append($"<label><input type=\"checkbox\" name=\"tag\" value=\"bolest\" {chkBolest} /> bolest</label>");

sb.Append("</div>\n</div>\n");

sb.Append("<div style=\"display:flex; gap:0.5rem; flex-wrap:wrap\">\n");
sb.Append("<button type=\"submit\">Filtrovat</button>\n");
sb.Append("<a class=\"btn-secondary\" href=\"/zaznamy?last7=1\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Posledních 7 dní</a>\n");
sb.Append("<a class=\"btn-secondary\" href=\"/zaznamy?last30=1\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Posledních 30 dní</a>\n");
sb.Append("<a class=\"btn-secondary\" href=\"/zaznamy?last90=1\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Posledních 90 dní</a>\n");
sb.Append("<a class=\"btn-secondary\" href=\"/zaznamy\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Reset</a>\n");
sb.Append("</div>\n");

sb.Append("</form>\n</div>\n");

sb.Append($"<p style=\"color:#64748b; margin:0 0 0.75rem\">Nalezeno: <b>{zaznamy.Count}</b></p>");

if (zaznamy.Count == 0)
{
sb.Append("<p>Žádné záznamy pro zvolený filtr.</p>");
return Results.Content(PageLayout("Záznamy", sb.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
}

sb.Append("<div class=\"card\"><table><thead><tr><th>Datum</th><th>Typ</th><th>Detaily</th><th></th></tr></thead><tbody>");

foreach (var z in zaznamy.OrderByDescending(z => z.Datum))
{
var typText = GetTypeLabel(z, customTypeMap, customTypeMapAll);

string detaily;
if (!IsBuiltInType(z.Typ))
{
var typeId = 0;
if (user.IsAdmin && targetUser is null)
{
customTypeIdByUserKey.TryGetValue((z.UserId, z.Typ), out typeId);
}
else
{
customTypeIdByKey.TryGetValue(z.Typ, out typeId);
}
if (typeId != 0 && customFieldsByTypeId.TryGetValue(typeId, out var fields))
{
var values = customValuesByRecord.TryGetValue(z.Id, out var map) ? map : new Dictionary<int, string>();
var parts = new List<string>();
foreach (var f in fields)
{
if (!values.TryGetValue(f.Id, out var v) || string.IsNullOrWhiteSpace(v)) continue;
var unit = string.IsNullOrWhiteSpace(f.Unit) ? "" : $" {f.Unit}";
if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
{
parts.Add($"{H(f.Label)}: ano");
}
else
{
parts.Add($"{H(f.Label)}: {H(v)}{H(unit)}");
}
}
detaily = parts.Count == 0 ? "—" : string.Join(", ", parts);
}
else
{
detaily = "—";
}
}
else
{
detaily = z.Typ switch
{
"beh" => $"Vzdálenost: {z.VzdalenostKm:0.##} km, tempo: {H(z.Tempo)}, převýšení: {z.PrevyseniM} m, tep: {z.Tep}",
"kolo" => $"Vzdálenost: {z.VzdalenostKm:0.##} km, doba: {z.DobaMinuty} min, převýšení: {z.PrevyseniM} m, tep: {z.Tep}",
"turistika" => $"Vzdálenost: {z.VzdalenostKm:0.##} km, doba: {z.DobaMinuty} min, převýšení: {z.PrevyseniM} m, tep: {z.Tep}",
"plavani" => $"Bazén: {z.VelikostBazenuM} m, vzdálenost: {z.VzdalenostM} m, doba: {z.DobaPlavaniMin} min",
_ => $"{H(z.Cviceni)}, série: {z.Serie}, opakování: {z.Opakovani}, doba: {z.DobaMinuty} min"
};
}

sb.Append("<tr>");
sb.Append($"<td>{z.Datum:dd.MM.yyyy}</td>");
sb.Append($"<td>{typText}</td>");
if (!string.IsNullOrWhiteSpace(z.Tagy))
{
var chips = string.Join(" ", TagSet(z.Tagy).Select(t => $"<span style=\"display:inline-block; padding:0.15rem 0.5rem; border-radius:999px; background:#eef2ff; color:#1e3a8a; font-weight:700; font-size:0.85rem; margin-right:0.25rem\">#{H(t)}</span>"));
detaily += $"<div style=\"margin-top:0.35rem\">{chips}</div>";
}
if (!string.IsNullOrWhiteSpace(z.Poznamka))
{
detaily += $"<div style=\"color:#64748b; margin-top:0.25rem\"><b>Poznámka:</b> {H(z.Poznamka)}</div>";
}
if (!string.IsNullOrWhiteSpace(z.Pocasi))
{
detaily += $"<div style=\"color:#64748b; margin-top:0.25rem\"><b>Počasí:</b> {H(z.Pocasi)}</div>";
}
sb.Append($"<td>{detaily}</td>");
sb.Append("<td style=\"text-align:right; white-space:nowrap\">");
sb.Append($"<a class=\"btn-secondary\" href=\"/detail?id={z.Id}\" title=\"Detail\" style=\"display:inline-block; padding:0.55rem 0.7rem; border-radius:10px; text-decoration:none; font-weight:800; margin-right:0.35rem\">Detail</a>");
sb.Append($"<a class=\"btn-secondary\" href=\"/edit?id={z.Id}\" title=\"Upravit\" style=\"display:inline-block; padding:0.55rem 0.7rem; border-radius:10px; text-decoration:none; font-weight:800; margin-right:0.35rem\">Upravit</a>");
sb.Append("<form method=\"post\" action=\"/smazat\" style=\"display:inline\" onsubmit=\"return confirm('Smazat záznam?')\">");
sb.Append($"<input type=\"hidden\" name=\"id\" value=\"{z.Id}\" />");
sb.Append("<button class=\"btn-secondary\" type=\"submit\" title=\"Smazat\">Smazat</button>");
sb.Append("</form>");
sb.Append("</td>");
sb.Append("</tr>");
}

sb.Append("</tbody></table></div>");
return Results.Content(PageLayout("Záznamy", sb.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/statistiky", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var qsUser = context.Request.Query["user"].ToString();
int? statsUserId = null;
User? statsUser = null;
if (user.IsAdmin && int.TryParse(qsUser, out var uid))
{
statsUser = DbGetUserById(uid);
if (statsUser is not null) statsUserId = statsUser.Id;
}

var zaznamy = DbGetAll(user.IsAdmin ? statsUserId : user.Id);
var showCustom = !user.IsAdmin || statsUserId is not null;
var customOwnerId = statsUserId ?? user.Id;
var customTypes = showCustom ? DbGetCustomTypes(customOwnerId) : new List<CustomType>();
var customFields = showCustom ? DbGetCustomFieldsForTypes(customTypes.Select(t => t.Id).ToList()) : new List<CustomField>();
var customFieldsByTypeId = customFields.Count == 0 ? new Dictionary<int, List<CustomField>>() : customFields.GroupBy(f => f.TypeId).ToDictionary(g => g.Key, g => g.ToList());
var customValuesByRecord = showCustom && zaznamy.Count > 0 ? DbGetCustomValuesForRecords(zaznamy.Select(z => z.Id).ToList()) : new Dictionary<int, Dictionary<int, string>>();
var rangeParam = context.Request.Query["range"].ToString();
var rangeDays = int.TryParse(rangeParam, out var days) ? days : 0;
var qsFrom = context.Request.Query["from"].ToString();
var qsTo = context.Request.Query["to"].ToString();
static DateTime? TryParseDateStats(string? s)
{
var t = (s ?? "").Trim();
if (string.IsNullOrWhiteSpace(t)) return null;
if (DateTime.TryParseExact(t, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var iso)) return iso.Date;
if (DateTime.TryParse(t, CultureInfo.CurrentCulture, DateTimeStyles.None, out var any)) return any.Date;
if (DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.None, out any)) return any.Date;
return null;
}
var from = TryParseDateStats(qsFrom);
var to = TryParseDateStats(qsTo);
if (from is not null || to is not null)
{
var f = from ?? DateTime.MinValue.Date;
var t = to ?? DateTime.MaxValue.Date;
zaznamy = zaznamy.Where(z => z.Datum.Date >= f && z.Datum.Date <= t).ToList();
rangeDays = 0;
}
else if (rangeDays == 7 || rangeDays == 30 || rangeDays == 90)
{
var fromDate = DateTime.Today.AddDays(-rangeDays + 1);
zaznamy = zaznamy.Where(z => z.Datum.Date >= fromDate).ToList();
}

var customZaznamy = zaznamy;

var content = new StringBuilder();
var beh = zaznamy.Where(z => z.Typ == "beh").OrderBy(z => z.Datum).ToList();
var kolo = zaznamy.Where(z => z.Typ == "kolo").OrderBy(z => z.Datum).ToList();
var turistika = zaznamy.Where(z => z.Typ == "turistika").OrderBy(z => z.Datum).ToList();
var cviceni = zaznamy.Where(z => z.Typ == "cviceni").OrderBy(z => z.Datum).ToList();
var plavani = zaznamy.Where(z => z.Typ == "plavani").OrderBy(z => z.Datum).ToList();

var totalBehKm = beh.Sum(v => v.VzdalenostKm);
var totalBehCount = beh.Count;
var totalKoloKm = kolo.Sum(v => v.VzdalenostKm);
var totalKoloCount = kolo.Count;
var totalKoloMin = kolo.Sum(v => v.DobaMinuty);
var totalTurKm = turistika.Sum(v => v.VzdalenostKm);
var totalTurCount = turistika.Count;
var totalTurMin = turistika.Sum(v => v.DobaMinuty);
var totalCviceniCount = cviceni.Count;
var totalCviceniMin = cviceni.Sum(v => v.DobaMinuty);
var totalCviceniSerie = cviceni.Sum(v => v.Serie);
var totalPlavaniCount = plavani.Count;
var totalPlavaniMin = plavani.Sum(v => v.DobaPlavaniMin);
var totalPlavaniM = plavani.Sum(v => v.VzdalenostM);
var lastDate = zaznamy.Count == 0 ? "-" : zaznamy.Max(z => z.Datum).ToString("dd.MM.yyyy");
var rangeLabel = rangeDays switch
{
7 => "Posledních 7 dní",
30 => "Posledních 30 dní",
90 => "Posledních 90 dní",
_ => "Celé období"
};
if (from is not null || to is not null)
{
var fromText = from is null ? "od začátku" : from.Value.ToString("dd.MM.yyyy");
var toText = to is null ? "dnes" : to.Value.ToString("dd.MM.yyyy");
rangeLabel = $"Rozsah {fromText} - {toText}";
}

var paceVals = beh.Select(z => { TryParsePaceMinPerKm(z.Tempo, out var m); return m; }).Where(m => m > 0).ToList();
var avgPace = paceVals.Count == 0 ? "-" : FormatPace(paceVals.Average());
var userLabel = statsUser is null ? "" : $" - Uživatel: <b>{H(statsUser.Username)}</b>";

content.Append($"""
<section class="stat-hero">
<div class="stat-hero-left">
<div class="stat-kicker">Souhrn</div>
<h2>Statistiky</h2>
<p class="stat-hero-sub">{rangeLabel}{userLabel} - Celkem záznamů: <b>{zaznamy.Count}</b> - Poslední aktivita: <b>{lastDate}</b></p>
</div>
<div class="stat-hero-right kpi-grid">
<div class="kpi-card kpi-total">
<div class="kpi-label">Celkem</div>
<div class="kpi-value">{zaznamy.Count}</div>
<div class="kpi-note">všechny záznamy</div>
</div>
""");

if (totalBehCount > 0)
{
content.Append($"""
<div class="kpi-card kpi-run">
<div class="kpi-label">Běh</div>
<div class="kpi-value">{FormatNumber(totalBehKm)} km</div>
<div class="kpi-note">{totalBehCount} tréninků - prům. tempo {avgPace}</div>
</div>
""");
}

if (totalKoloCount > 0)
{
content.Append($"""
<div class="kpi-card kpi-bike">
<div class="kpi-label">Kolo</div>
<div class="kpi-value">{FormatNumber(totalKoloKm)} km</div>
<div class="kpi-note">{totalKoloCount} tréninků - {totalKoloMin} min</div>
</div>
""");
}

if (totalTurCount > 0)
{
content.Append($"""
<div class="kpi-card kpi-hike">
<div class="kpi-label">Turistika</div>
<div class="kpi-value">{FormatNumber(totalTurKm)} km</div>
<div class="kpi-note">{totalTurCount} tréninků - {totalTurMin} min</div>
</div>
""");
}

if (totalCviceniCount > 0)
{
content.Append($"""
<div class="kpi-card kpi-gym">
<div class="kpi-label">Cvičení</div>
<div class="kpi-value">{totalCviceniMin} min</div>
<div class="kpi-note">{totalCviceniCount} tréninků - {totalCviceniSerie} sérií</div>
</div>
""");
}

if (totalPlavaniCount > 0)
{
content.Append($"""
<div class="kpi-card kpi-swim">
<div class="kpi-label">Plavání</div>
<div class="kpi-value">{totalPlavaniM} m</div>
<div class="kpi-note">{totalPlavaniCount} tréninků - {totalPlavaniMin} min</div>
</div>
""");
}

content.Append("""
</div>
</section>
""");
if (user.IsAdmin)
{
var allUsers = DbGetAllUsers();
content.Append("<form method=\"get\" action=\"/statistiky\" style=\"margin:0 0 0.75rem\">");
content.Append("<label style=\"font-weight:700; display:block; margin-bottom:0.35rem\">Uživatel</label>");
content.Append("<select name=\"user\" onchange=\"this.form.submit()\" style=\"max-width:260px\">");
content.Append("<option value=\"\">Všichni</option>");
foreach (var u in allUsers)
{
var selected = statsUserId == u.Id ? "selected" : "";
content.Append($"<option value=\"{u.Id}\" {selected}>{H(u.Username)}</option>");
}
content.Append("</select>");
content.Append("</form>");
}

var userQuery = statsUserId is null ? "" : $"user={statsUserId.Value}";
var userQueryPrefix = string.IsNullOrWhiteSpace(userQuery) ? "" : "?" + userQuery;
var userQuerySuffix = string.IsNullOrWhiteSpace(userQuery) ? "" : "&" + userQuery;
content.Append("<div class=\"range-tabs\">");
content.Append($"<a class=\"range-btn {(rangeDays == 0 ? "active" : "")}\" href=\"/statistiky{userQueryPrefix}\">Vše</a>");
content.Append($"<a class=\"range-btn {(rangeDays == 7 ? "active" : "")}\" href=\"/statistiky?range=7{userQuerySuffix}\">7 dnů</a>");
content.Append($"<a class=\"range-btn {(rangeDays == 30 ? "active" : "")}\" href=\"/statistiky?range=30{userQuerySuffix}\">30 dnů</a>");
content.Append($"<a class=\"range-btn {(rangeDays == 90 ? "active" : "")}\" href=\"/statistiky?range=90{userQuerySuffix}\">90 dnů</a>");
content.Append("</div>");
content.Append($"""
<form method="get" action="/statistiky" class="range-form">
<div class="field">
<label for="from">Od</label>
<input id="from" name="from" type="date" value="{H(from is null ? "" : DateToIso(from.Value))}" />
</div>
<div class="field">
<label for="to">Do</label>
<input id="to" name="to" type="date" value="{H(to is null ? "" : DateToIso(to.Value))}" />
</div>
{(statsUserId is null ? "" : $"<input type=\"hidden\" name=\"user\" value=\"{statsUserId.Value}\" />")}
<div style="display:flex; gap:0.5rem; flex-wrap:wrap; align-items:flex-end">
<button type="submit">Použít</button>
<a class="btn-secondary" href="/statistiky" style="display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none">Reset</a>
</div>
</form>
""");
content.Append("""
<div class="tabs">
<button class="tab-btn active" data-tab="beh">
<span class="tab-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<circle cx="16" cy="5" r="2"></circle>
<path d="M10 20l3-5 3 2"></path>
<path d="M9 12l4-2 3 2"></path>
<path d="M6 14l3-2"></path>
<path d="M13 7l-2 5"></path>
</svg>
</span>
Běh
</button>
<button class="tab-btn" data-tab="kolo">
<span class="tab-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<circle cx="6" cy="16" r="3.5"></circle>
<circle cx="18" cy="16" r="3.5"></circle>
<path d="M6 16l4-8h4l2 4"></path>
<path d="M12 8l-2 4"></path>
</svg>
</span>
Kolo
</button>
<button class="tab-btn" data-tab="turistika">
<span class="tab-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M3 18l6-9 4 6 2-3 6 6"></path>
<path d="M9 9h2"></path>
</svg>
</span>
Turistika
</button>
<button class="tab-btn" data-tab="cviceni">
<span class="tab-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M4 10v4"></path>
<path d="M20 10v4"></path>
<path d="M8 8v8"></path>
<path d="M16 8v8"></path>
<path d="M4 12h16"></path>
</svg>
</span>
Cvičení
</button>
<button class="tab-btn" data-tab="plavani">
<span class="tab-icon" aria-hidden="true">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<path d="M4 18c2 2 4 2 6 0 2 2 4 2 6 0 2 2 4 2 6 0"></path>
<path d="M8 8c1-2 3-2 4 0"></path>
<path d="M6 12c2-2 6-2 8 0"></path>
</svg>
</span>
Plavání
</button>
""");
foreach (var ct in customTypes)
{
content.Append($"<button class=\"tab-btn\" data-tab=\"{H(ct.Key)}\">");
content.Append("<span class=\"tab-icon\" aria-hidden=\"true\">");
content.Append("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M4 19h16\"/><path d=\"M7 19V9\"/><path d=\"M12 19V5\"/><path d=\"M17 19v-7\"/></svg>");
content.Append("</span>");
content.Append(H(ct.Name));
content.Append("</button>");
}
content.Append("</div>");

// --- BĚH ---
var behBlocks = new StringBuilder();
if (beh.Count == 0)
{
behBlocks.Append("<p>Žádná data pro běh.</p>");
}
else
{
behBlocks.Append("<div class=\"metric-switch\">");
behBlocks.Append("<button class=\"metric-btn active\" data-metric=\"vzdalenost\" type=\"button\">Vzdálenost</button>");
behBlocks.Append("<button class=\"metric-btn\" data-metric=\"tempo\" type=\"button\">Tempo</button>");
behBlocks.Append("</div>");
// vzdálenost po dnech
var distSeries = beh
.GroupBy(z => z.Datum.Date)
.Select(g => (x: g.Key, y: g.Sum(v => v.VzdalenostKm)))
.OrderBy(p => p.x)
.ToList();

// průměrné tempo po dnech
var paceSeries = beh
.Where(z => TryParsePaceMinPerKm(z.Tempo, out _))
.GroupBy(z => z.Datum.Date)
.Select(g =>
{
var vals = g.Select(x => { TryParsePaceMinPerKm(x.Tempo, out var m); return m; }).Where(m => m > 0).ToList();
var avg = vals.Count == 0 ? 0 : vals.Average();
return (x: g.Key, y: avg);
})
.Where(p => p.y > 0)
.OrderBy(p => p.x)
.ToList();

behBlocks.Append("<div class=\"chart-grid\">");
behBlocks.Append("<div class=\"chart-card\" data-metric=\"vzdalenost\">" + SvgLineChart(distSeries, "Vzdálenost (km) v čase", "km", invertY: false) + "</div>");
behBlocks.Append("<div class=\"chart-card\" data-metric=\"tempo\">" + SvgLineChart(paceSeries, "Průměrné tempo (min/km) v čase", "min/km", invertY: true) + "</div>");
behBlocks.Append("</div>");
}

content.Append($"<section class=\"tab-panel active\" id=\"tab-beh\">{behBlocks}</section>");

// --- KOLO ---
var koloBlocks = new StringBuilder();
if (kolo.Count == 0)
{
koloBlocks.Append("<p>Žádná data pro kolo.</p>");
}
else
{
 koloBlocks.Append("<div class=\"metric-switch\">");
 koloBlocks.Append("<button class=\"metric-btn active\" data-metric=\"vzdalenost\" type=\"button\">Vzdálenost</button>");
 koloBlocks.Append("<button class=\"metric-btn\" data-metric=\"doba\" type=\"button\">Doba</button>");
 koloBlocks.Append("<button class=\"metric-btn\" data-metric=\"prevyseni\" type=\"button\">Převýšení</button>");
 koloBlocks.Append("</div>");
var vzdSeries = kolo.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: g.Sum(v => v.VzdalenostKm))).OrderBy(p => p.x).ToList();
var dobaSeries = kolo.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.DobaMinuty))).OrderBy(p => p.x).ToList();
var prevSeries = kolo.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.PrevyseniM))).OrderBy(p => p.x).ToList();

koloBlocks.Append("<div class=\"chart-grid\">");
koloBlocks.Append("<div class=\"chart-card\" data-metric=\"vzdalenost\">" + SvgLineChart(vzdSeries, "Vzdálenost (km) v čase", "km", invertY: false) + "</div>");
koloBlocks.Append("<div class=\"chart-card\" data-metric=\"doba\">" + SvgLineChart(dobaSeries, "Doba (min) v čase", "min", invertY: false) + "</div>");
koloBlocks.Append("<div class=\"chart-card\" data-metric=\"prevyseni\">" + SvgLineChart(prevSeries, "Převýšení (m) v čase", "m", invertY: false) + "</div>");
koloBlocks.Append("</div>");
}

content.Append($"<section class=\"tab-panel\" id=\"tab-kolo\">{koloBlocks}</section>");

// --- TURISTIKA ---
var turBlocks = new StringBuilder();
if (turistika.Count == 0)
{
turBlocks.Append("<p>Žádná data pro turistiku.</p>");
}
else
{
 turBlocks.Append("<div class=\"metric-switch\">");
 turBlocks.Append("<button class=\"metric-btn active\" data-metric=\"vzdalenost\" type=\"button\">Vzdálenost</button>");
 turBlocks.Append("<button class=\"metric-btn\" data-metric=\"doba\" type=\"button\">Doba</button>");
 turBlocks.Append("<button class=\"metric-btn\" data-metric=\"prevyseni\" type=\"button\">Převýšení</button>");
 turBlocks.Append("</div>");
var vzdSeries = turistika.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: g.Sum(v => v.VzdalenostKm))).OrderBy(p => p.x).ToList();
var dobaSeries = turistika.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.DobaMinuty))).OrderBy(p => p.x).ToList();
var prevSeries = turistika.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.PrevyseniM))).OrderBy(p => p.x).ToList();

turBlocks.Append("<div class=\"chart-grid\">");
turBlocks.Append("<div class=\"chart-card\" data-metric=\"vzdalenost\">" + SvgLineChart(vzdSeries, "Vzdálenost (km) v čase", "km", invertY: false) + "</div>");
turBlocks.Append("<div class=\"chart-card\" data-metric=\"doba\">" + SvgLineChart(dobaSeries, "Doba (min) v čase", "min", invertY: false) + "</div>");
turBlocks.Append("<div class=\"chart-card\" data-metric=\"prevyseni\">" + SvgLineChart(prevSeries, "Převýšení (m) v čase", "m", invertY: false) + "</div>");
turBlocks.Append("</div>");
}

content.Append($"<section class=\"tab-panel\" id=\"tab-turistika\">{turBlocks}</section>");

// --- CVIČENÍ ---
var cvBlocks = new StringBuilder();
if (cviceni.Count == 0)
{
cvBlocks.Append("<p>Žádná data pro cvičení.</p>");
}
else
{
cvBlocks.Append("<div class=\"metric-switch\">");
cvBlocks.Append("<button class=\"metric-btn active\" data-metric=\"serie\" type=\"button\">Série</button>");
cvBlocks.Append("<button class=\"metric-btn\" data-metric=\"opak\" type=\"button\">Opakování</button>");
cvBlocks.Append("<button class=\"metric-btn\" data-metric=\"doba\" type=\"button\">Doba</button>");
cvBlocks.Append("</div>");
var serieSeries = cviceni.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.Serie))).OrderBy(p => p.x).ToList();
var opakSeries = cviceni.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.Opakovani))).OrderBy(p => p.x).ToList();
var dobaSeries = cviceni.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.DobaMinuty))).OrderBy(p => p.x).ToList();

cvBlocks.Append("<div class=\"chart-grid\">");
cvBlocks.Append("<div class=\"chart-card\" data-metric=\"serie\">" + SvgLineChart(serieSeries, "Série v čase", "sérií", invertY: false) + "</div>");
cvBlocks.Append("<div class=\"chart-card\" data-metric=\"opak\">" + SvgLineChart(opakSeries, "Opakování v čase", "opak.", invertY: false) + "</div>");
cvBlocks.Append("<div class=\"chart-card\" data-metric=\"doba\">" + SvgLineChart(dobaSeries, "Doba (min) v čase", "min", invertY: false) + "</div>");
cvBlocks.Append("</div>");
}

content.Append($"<section class=\"tab-panel\" id=\"tab-cviceni\">{cvBlocks}</section>");

// --- PLAVÁNÍ ---
var plBlocks = new StringBuilder();
if (plavani.Count == 0)
{
plBlocks.Append("<p>Žádná data pro plavání.</p>");
}
else
{
plBlocks.Append("<div class=\"metric-switch\">");
plBlocks.Append("<button class=\"metric-btn active\" data-metric=\"vzdalenost\" type=\"button\">Vzdálenost</button>");
plBlocks.Append("<button class=\"metric-btn\" data-metric=\"doba\" type=\"button\">Doba</button>");
plBlocks.Append("<button class=\"metric-btn\" data-metric=\"bazen\" type=\"button\">Bazén</button>");
plBlocks.Append("</div>");
var vzdSeries = plavani.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.VzdalenostM))).OrderBy(p => p.x).ToList();
var dobaSeries = plavani.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Sum(v => v.DobaPlavaniMin))).OrderBy(p => p.x).ToList();
var bazSeries = plavani.GroupBy(z => z.Datum.Date).Select(g => (x: g.Key, y: (double)g.Max(v => v.VelikostBazenuM))).OrderBy(p => p.x).ToList();

plBlocks.Append("<div class=\"chart-grid\">");
plBlocks.Append("<div class=\"chart-card\" data-metric=\"vzdalenost\">" + SvgLineChart(vzdSeries, "Vzdálenost (m) v čase", "m", invertY: false) + "</div>");
plBlocks.Append("<div class=\"chart-card\" data-metric=\"doba\">" + SvgLineChart(dobaSeries, "Doba (min) v čase", "min", invertY: false) + "</div>");
plBlocks.Append("<div class=\"chart-card\" data-metric=\"bazen\">" + SvgLineChart(bazSeries, "Velikost bazénu (m) v čase", "m", invertY: false) + "</div>");
plBlocks.Append("</div>");
}

content.Append($"<section class=\"tab-panel\" id=\"tab-plavani\">{plBlocks}</section>");

foreach (var ct in customTypes)
{
var ctRecords = customZaznamy.Where(z => string.Equals(z.Typ, ct.Key, StringComparison.OrdinalIgnoreCase)).ToList();
var ctBlocks = new StringBuilder();
if (ctRecords.Count == 0)
{
ctBlocks.Append("<p>Žádná data pro tento typ.</p>");
}
else if (!customFieldsByTypeId.TryGetValue(ct.Id, out var fields))
{
ctBlocks.Append("<p>Žádné atributy.</p>");
}
else
{
var numFields = fields.Where(f => string.Equals(f.DataType, "number", StringComparison.OrdinalIgnoreCase)).ToList();
if (numFields.Count == 0)
{
ctBlocks.Append("<p>Žádné číselné atributy pro graf.</p>");
}
else
{
ctBlocks.Append("<div class=\"metric-switch\">");
foreach (var f in numFields)
{
var active = f == numFields[0] ? " active" : "";
ctBlocks.Append($"<button class=\"metric-btn{active}\" data-metric=\"{f.Id}\" type=\"button\">{H(f.Label)}</button>");
}
ctBlocks.Append("</div>");
ctBlocks.Append("<div class=\"chart-grid\">");
foreach (var f in numFields)
{
var series = ctRecords
.GroupBy(z => z.Datum.Date)
.Select(g =>
{
var sum = 0.0;
foreach (var rec in g)
{
if (!customValuesByRecord.TryGetValue(rec.Id, out var map)) continue;
if (!map.TryGetValue(f.Id, out var v)) continue;
sum += ParseDouble(v);
}
return (x: g.Key, y: sum);
})
.OrderBy(p => p.x)
.ToList();
var unit = string.IsNullOrWhiteSpace(f.Unit) ? "" : f.Unit;
ctBlocks.Append("<div class=\"chart-card\" data-metric=\"" + f.Id + "\">" + SvgLineChart(series, $"{f.Label} v čase", unit, invertY: false) + "</div>");
}
ctBlocks.Append("</div>");
}
}
content.Append($"<section class=\"tab-panel\" id=\"tab-{H(ct.Key)}\">{ctBlocks}</section>");
}

content.Append("""
<div id="chart-tooltip" class="chart-tooltip" aria-hidden="true"></div>
<script>
(function(){
function selectTab(name){
document.querySelectorAll('.tab-btn').forEach(function(b){
b.classList.toggle('active', b.getAttribute('data-tab')===name);
});
document.querySelectorAll('.tab-panel').forEach(function(p){
p.classList.toggle('active', p.id==='tab-'+name);
});
}
document.querySelectorAll('.tab-btn').forEach(function(btn){
btn.addEventListener('click', function(){
selectTab(btn.getAttribute('data-tab'));
});
});

function initMetricSwitchers(){
document.querySelectorAll('.metric-switch').forEach(function(sw){
var buttons = sw.querySelectorAll('.metric-btn');
if (buttons.length === 0) return;
function activate(metric){
buttons.forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-metric')===metric); });
var panel = sw.closest('.tab-panel');
if (!panel) return;
panel.querySelectorAll('.chart-card').forEach(function(card){
card.style.display = (card.getAttribute('data-metric')===metric) ? '' : 'none';
});
}
buttons.forEach(function(btn){
btn.addEventListener('click', function(){
activate(btn.getAttribute('data-metric'));
});
});
activate(buttons[0].getAttribute('data-metric'));
});
}
initMetricSwitchers();

var tooltip = document.getElementById('chart-tooltip');
var activePoint = null;
var hideTimer = null;
function showTipFor(point){
if (!point) return;
var date = point.getAttribute('data-date') || '';
var val = point.getAttribute('data-display') || '';
var unit = point.getAttribute('data-unit') || '';
tooltip.textContent = date + ' - ' + val + (unit ? ' ' + unit : '');
tooltip.style.opacity = '1';
tooltip.style.transform = 'translateY(0)';
tooltip.setAttribute('aria-hidden', 'false');
}
function moveTip(e){
if (tooltip.getAttribute('aria-hidden') === 'true') return;
var x = e.clientX + 12;
var y = e.clientY - 12;
tooltip.style.left = x + 'px';
tooltip.style.top = y + 'px';
}
function hideTip(){
tooltip.style.opacity = '0';
tooltip.style.transform = 'translateY(6px)';
tooltip.setAttribute('aria-hidden', 'true');
activePoint = null;
}
function scheduleHide(){
if (hideTimer) clearTimeout(hideTimer);
hideTimer = setTimeout(hideTip, 80);
}
function findPointFromEvent(e){
if (!e) return null;
var path = e.composedPath ? e.composedPath() : null;
if (path && path.length) {
for (var i = 0; i < path.length; i++) {
var el = path[i];
if (el && el.classList && el.classList.contains('chart-point')) return el;
}
}
var t = e.target;
if (t && t.classList && t.classList.contains('chart-point')) return t;
return null;
}
document.querySelectorAll('.chart-svg').forEach(function(svg){
svg.addEventListener('pointermove', function(e){
var pt = findPointFromEvent(e);
if (pt) {
if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
if (activePoint !== pt) { activePoint = pt; showTipFor(pt); }
moveTip(e);
return;
}
if (activePoint) scheduleHide();
});
svg.addEventListener('pointerleave', function(){
scheduleHide();
});
});
})();
</script>
""");

return Results.Content(PageLayout("Statistiky", content.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/detail", (HttpContext context) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
if (!int.TryParse(context.Request.Query["id"].ToString(), out var id))
return Results.Redirect("/zaznamy");

var z = DbGetById(id, user.IsAdmin ? null : user.Id);
if (z is null)
return Results.Content(PageLayout("Detail", "<p>Záznam nenalezen.</p>", user.Username, user.IsAdmin), "text/html; charset=utf-8");

var ownerUserId = user.IsAdmin ? z.UserId : user.Id;
CustomType? customType = null;
if (!IsBuiltInType(z.Typ))
{
customType = DbGetCustomTypeByKey(ownerUserId, z.Typ);
}
var typText = customType?.Name ?? (z.Typ switch
{
"beh" => "Běh",
"kolo" => "Kolo",
"turistika" => "Turistika",
"plavani" => "Plavání",
"cviceni" => "Cvičení",
_ => z.Typ
});

var body = new StringBuilder();
body.Append($"<h2>Detail záznamu</h2><p style=\"color:#64748b;margin-top:-0.25rem\">ID: {z.Id}</p>");
body.Append("<div style=\"display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem 1rem\">");
body.Append($"<div><b>Datum:</b> {z.Datum:dd.MM.yyyy}</div>");
body.Append($"<div><b>Typ:</b> {typText}</div>");
if (!string.IsNullOrWhiteSpace(z.Pocasi))
body.Append($"<div><b>Počasí:</b> {H(z.Pocasi)}</div>");
if (!string.IsNullOrWhiteSpace(z.Tagy))
body.Append($"<div><b>Tagy:</b> {H(z.Tagy)}</div>");
if (!string.IsNullOrWhiteSpace(z.Poznamka))
body.Append($"<div style=\"grid-column:1/-1\"><b>Poznámka:</b> {H(z.Poznamka)}</div>");
body.Append("</div>");

body.Append("<hr style=\"margin:1rem 0; border:none; border-top:1px solid var(--border)\" />");

var detaily = z.Typ switch
{
"beh" => $"<b>Vzdálenost:</b> {z.VzdalenostKm:0.##} km<br /><b>Tempo:</b> {H(z.Tempo)}<br /><b>Převýšení:</b> {z.PrevyseniM} m<br /><b>Tep:</b> {z.Tep}",
"kolo" => $"<b>Vzdálenost:</b> {z.VzdalenostKm:0.##} km<br /><b>Doba:</b> {z.DobaMinuty} min<br /><b>Převýšení:</b> {z.PrevyseniM} m<br /><b>Tep:</b> {z.Tep}",
"turistika" => $"<b>Vzdálenost:</b> {z.VzdalenostKm:0.##} km<br /><b>Doba:</b> {z.DobaMinuty} min<br /><b>Převýšení:</b> {z.PrevyseniM} m<br /><b>Tep:</b> {z.Tep}",
"plavani" => $"<b>Velikost bazénu:</b> {z.VelikostBazenuM} m<br /><b>Vzdálenost:</b> {z.VzdalenostM} m<br /><b>Doba:</b> {z.DobaPlavaniMin} min",
_ => $"<b>Cvičení:</b> {H(z.Cviceni)}<br /><b>Série:</b> {z.Serie}<br /><b>Opakování:</b> {z.Opakovani}<br /><b>Doba:</b> {z.DobaMinuty} min"
};
if (customType is not null)
{
var fields = DbGetCustomFieldsByTypeId(customType.Id);
var values = DbGetCustomValuesByRecord(z.Id);
var parts = new List<string>();
foreach (var f in fields)
{
if (!values.TryGetValue(f.Id, out var v) || string.IsNullOrWhiteSpace(v)) continue;
var unit = string.IsNullOrWhiteSpace(f.Unit) ? "" : $" {H(f.Unit)}";
if (string.Equals(f.DataType, "bool", StringComparison.OrdinalIgnoreCase))
parts.Add($"<b>{H(f.Label)}:</b> ano");
else
parts.Add($"<b>{H(f.Label)}:</b> {H(v)}{unit}");
}
detaily = parts.Count == 0 ? "<b>Detaily:</b> -" : string.Join("<br />", parts);
}
body.Append($"<div>{detaily}</div>");

var fotos = DbGetPhotosByRecord(z.Id, user.Id, user.IsAdmin);
var images = fotos.Where(f => f.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)).ToList();
var files = fotos.Where(f => !f.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase)).ToList();
if (images.Count > 0)
{
body.Append("<h3 style=\"margin-top:1rem\">Fotky</h3>");
body.Append("<div class=\"photo-grid\">");
foreach (var f in images)
{
var title = string.IsNullOrWhiteSpace(f.OriginalName) ? "Foto" : H(f.OriginalName);
body.Append($"<a href=\"/fotky/{f.Id}\" target=\"_blank\" title=\"{title}\"><img src=\"/fotky/{f.Id}\" alt=\"{title}\" loading=\"lazy\" /></a>");
}
body.Append("</div>");
}
if (files.Count > 0)
{
body.Append("<h3 style=\"margin-top:1rem\">Soubory</h3>");
body.Append("<div style=\"display:flex; flex-direction:column; gap:0.35rem\">");
foreach (var f in files)
{
var title = string.IsNullOrWhiteSpace(f.OriginalName) ? "Soubor" : H(f.OriginalName);
body.Append($"<a href=\"/fotky/{f.Id}\" style=\"color:#2563eb; text-decoration:none\">{title}</a>");
}
body.Append("</div>");
}

body.Append("<div class=\"actions\" style=\"display:flex; gap:0.5rem; flex-wrap:wrap\">");
body.Append($"<a class=\"btn-secondary\" href=\"/edit?id={z.Id}\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Upravit</a>");
body.Append("<a class=\"btn-secondary\" href=\"/zaznamy\" style=\"display:inline-block; padding:0.6rem 0.9rem; border-radius:10px; text-decoration:none\">Zpět</a>");
body.Append("</div>");

return Results.Content(PageLayout("Detail", body.ToString(), user.Username, user.IsAdmin), "text/html; charset=utf-8");
});

app.MapGet("/fotky/{id:int}", (HttpContext context, int id) =>
{
var user = CurrentUser(context);
if (user is null) return Results.Redirect("/login");
var foto = DbGetPhotoById(id, user.Id, user.IsAdmin);
if (foto is null) return Results.NotFound();
var path = Path.Combine(uploadsDir, foto.FileName);
if (!File.Exists(path)) return Results.NotFound();
var contentType = string.IsNullOrWhiteSpace(foto.ContentType) ? "application/octet-stream" : foto.ContentType;
if (contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
{
return Results.File(path, contentType);
}
return Results.File(path, contentType, foto.OriginalName);
});

app.Run();

static string PageLayout(string title, string bodyHtml, string? username = null, bool isAdmin = false)
{
var sb = new StringBuilder();
sb.Append("""
<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
""");
sb.Append($"<title>{H(title)}</title>");
sb.Append("""
<style>
:root {
--bg: #f5f7fb;
--card: #ffffff;
--text: #0f172a;
--muted: #64748b;
--primary: #0f172a;
--primary2: #1f2937;
--border: #e5e7eb;
--btn-radius: 10px;
--btn-pad-y: 0.6rem;
--btn-pad-x: 0.9rem;
--btn-height: 34px;
--btn-font: 16px;
--menu-new: #f97316;
--menu-list: #2563eb;
--menu-stats: #10b981;
--chart-line-start: #0ea5e9;
--chart-line-end: #22c55e;
--chart-area: rgba(14,165,233,0.18);
--chart-grid: #e2e8f0;
--chart-ink: #0f172a;
--chart-avg: #94a3b8;
--chart-trend: #f59e0b;
--chart-ma: #16a34a;
}
*, *::before, *::after { box-sizing: border-box; }
body { font-family: "Space Grotesk", "Manrope", "IBM Plex Sans", "Segoe UI", sans-serif; margin: 0; background: var(--bg); color: var(--text); }
header { background: var(--primary); color: white; padding: 1rem 1.25rem; }
header h1 { margin: 0; font-size: 1.25rem; }
.layout { display:flex; align-items: stretch; min-height: calc(100vh - 64px); }
nav { background: var(--primary2); padding: 1rem 0.9rem; display:flex; gap: 0.6rem; flex-direction: column; align-items: stretch; min-width: 220px; }
nav a { color: white; text-decoration: none; font-weight: 600; opacity: 0.95; padding: 0.35rem 0.5rem; border-radius: 8px; }
nav a:hover { background: rgba(255,255,255,0.08); opacity: 1; text-decoration: none; }
.nav-user { margin-top: auto; color: #cbd5e1; font-weight: 600; padding: 0.35rem 0.5rem; }
.container { max-width: 1100px; margin: 1.25rem; padding: 0 1rem; flex:1; }
@media (max-width: 900px) {
.layout { flex-direction: column; min-height: auto; }
nav { flex-direction: row; flex-wrap: wrap; min-width: auto; padding: 0.6rem 0.75rem; }
.nav-user { margin-top: 0; margin-left: auto; }
}
@media (max-width: 720px) {
header h1 { font-size: 1.1rem; }
.container { margin: 0.75rem; padding: 0; }
nav { padding: 0.5rem 0.6rem; gap: 0.4rem; }
nav a { font-size: 0.95rem; }
.nav-user { flex-basis: 100%; margin-left: 0; }
.card { overflow-x: auto; }
table { min-width: 520px; }
.tag-list { gap: 0.5rem; }
.tag-list label { font-size: 0.9rem; }
.range-form { gap: 0.5rem; }
.range-form .field { min-width: 0; flex: 1 1 100%; }
.range-form button, .range-form .btn-secondary { flex: 1 1 120px; justify-content: center; }
.tabs { flex-wrap: wrap; }
.tab-btn { flex: 1 1 120px; justify-content: center; }
.filters-form { gap: 0.5rem; }
.filters-form .field { min-width: 0; flex: 1 1 100%; }
}
.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 2px 10px rgba(15,23,42,0.06); padding: 1rem; }
.grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem 1rem; align-items: start; }
@media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
.field { min-width: 0; }
.field label { display:block; font-size: 0.9rem; color: var(--muted); margin-bottom: 0.25rem; }
.field input, .field select { width: 100%; padding: 0.55rem 0.65rem; border: 1px solid var(--border); border-radius: 10px; font-size: 1rem; background: white; }
.field input[type="date"] { min-width: 0; width: 100%; max-width: 100%; display: block; height: 40px; line-height: 1.2; -webkit-appearance: none; appearance: none; }
.field input[type="date"]::-webkit-inner-spin-button,
.field input[type="date"]::-webkit-clear-button { display: none; }
.field input[type="date"]::-webkit-calendar-picker-indicator { opacity: 0.35; }
.actions { margin-top: 1rem; }
.tag-list { display:flex; gap:0.75rem; flex-wrap:wrap; }
.tag-list label { display:inline-flex; align-items:center; gap:0.4rem; font-size: 0.95rem; color: var(--text); white-space: nowrap; }
.tag-list input { width: auto; margin: 0; }
.inline-selects { display:flex; gap:0.45rem; flex-wrap:wrap; align-items:center; }
.inline-selects select { flex: 1 1 120px; min-width: 0; }
.inline-part { display:inline-flex; align-items:center; gap:0.35rem; }
.inline-sep { font-weight: 700; color: var(--muted); }
.inline-suffix { font-size: 0.85rem; color: var(--muted); }
button, .btn-secondary, .tab-btn, .range-btn, .metric-btn, .file-label { display: inline-flex; align-items: center; gap: 0.45rem; border-radius: var(--btn-radius); padding: 0 var(--btn-pad-x); height: var(--btn-height); font-weight: 700; font-size: var(--btn-font); line-height: 1; cursor: pointer; text-decoration: none; border: 1px solid #cbd5e1; background: #e2e8f0; color: #0f172a; }
button:hover, .btn-secondary:hover, .tab-btn:hover, .range-btn:hover, .metric-btn:hover, .file-label:hover { filter: brightness(0.95); }
.icon-inline { width: 18px; height: 18px; display:inline-flex; align-items:center; justify-content:center; }
.icon-inline svg { width: 18px; height: 18px; }
.file-input { position: absolute; left: -9999px; }
.file-label { display:inline-flex; align-items:center; gap:0.45rem; cursor: pointer; }
.field label.file-label { display:inline-flex; }
.typ-section { margin-top: 1rem; padding-top: 0.25rem; }
.typ-section h3 { margin: 0.5rem 0 0.5rem; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.6rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { background: #f1f5f9; font-size: 0.9rem; color: #0f172a; }

.tabs { display:flex; gap: 0.5rem; margin: 0.5rem 0 1rem; }
.tab-btn { font-weight: 700; }
.tab-icon { width: 18px; height: 18px; display:inline-flex; align-items:center; justify-content:center; color:#475569; }
.tab-icon svg { width: 18px; height: 18px; }
.tab-btn.active { background: #e2e8f0; color: #0f172a; border-color: #cbd5e1; }
.tab-btn.active .tab-icon { color: #475569; }
.tab-panel { display:none; }
.tab-panel.active { display:block; }

.metric-switch { display:flex; gap: 0.5rem; flex-wrap:wrap; margin: 0.5rem 0 0.75rem; }
.metric-btn { border-radius: var(--btn-radius); }
.metric-btn.active { background: #e2e8f0; color: #0f172a; border-color: #cbd5e1; }

.range-tabs { display:flex; gap: 0.5rem; flex-wrap:wrap; margin: 0 0 0.75rem; }
.range-btn { border-radius: var(--btn-radius); }
.range-btn.active { background: #e2e8f0; color: #0f172a; border-color: #cbd5e1; }
.range-form { display:flex; gap: 0.75rem; flex-wrap:wrap; align-items:flex-end; margin: 0 0 1rem; }
.range-form .field { min-width: 160px; }
.range-form .btn-secondary { display:flex; justify-content:center; }
.filters-form .field { min-width: 160px; }
.range-tabs a { display:inline-flex; align-items:center; gap:0.35rem; padding: 0.45rem 0.75rem; border-radius: 999px; background: #e2e8f0; color: #0f172a; text-decoration:none; font-weight: 700; border: 1px solid #cbd5e1; }
.range-tabs a.active { background: var(--primary); color: white; border-color: var(--primary); }

.stat-hero { display:flex; gap: 1rem; align-items: stretch; background: linear-gradient(120deg, #0f172a, #1e293b); color: #f8fafc; border-radius: 16px; padding: 1.25rem; margin-bottom: 1rem; box-shadow: 0 12px 24px rgba(15,23,42,0.18); }
.stat-hero-left { flex: 1; min-width: 220px; }
.stat-hero-right { flex: 2; }
.stat-kicker { text-transform: uppercase; letter-spacing: 0.18em; font-size: 0.7rem; color: #c7d2fe; font-weight: 700; }
.stat-hero h2 { margin: 0.2rem 0 0; font-size: 1.7rem; letter-spacing: 0.02em; }
.stat-hero-sub { margin: 0.45rem 0 0; color: #e2e8f0; }
.kpi-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem; }
.kpi-card { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.25); border-radius: 14px; padding: 0.8rem; }
.kpi-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.12em; color: #e2e8f0; font-weight: 700; }
.kpi-value { font-size: 1.25rem; font-weight: 900; margin-top: 0.2rem; }
.kpi-note { font-size: 0.85rem; color: #e2e8f0; margin-top: 0.25rem; }
.kpi-total { border-color: rgba(148,163,184,0.7); }
.kpi-total .kpi-value { color: #e2e8f0; }
.kpi-run { border-color: rgba(249,115,22,0.7); }
.kpi-run .kpi-value { color: #fdba74; }
.kpi-bike { border-color: rgba(14,165,233,0.7); }
.kpi-bike .kpi-value { color: #7dd3fc; }
.kpi-hike { border-color: rgba(34,197,94,0.7); }
.kpi-hike .kpi-value { color: #86efac; }
.kpi-gym { border-color: rgba(59,130,246,0.7); }
.kpi-gym .kpi-value { color: #93c5fd; }
.kpi-swim { border-color: rgba(16,185,129,0.7); }
.kpi-swim .kpi-value { color: #6ee7b7; }
@media (max-width: 980px) { .stat-hero { flex-direction: column; } .kpi-grid { grid-template-columns: 1fr; } }

.menu-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }
.menu-card { display:block; padding: 1.1rem 1rem 1rem; border-radius: 16px; border: 2px solid var(--text); text-decoration:none; color: var(--text); font-weight: 800; background: #f8fafc; box-shadow: 0 6px 0 rgba(15,23,42,0.12); transition: transform 120ms ease, box-shadow 120ms ease; }
.menu-card:hover { transform: translateY(-3px); box-shadow: 0 10px 0 rgba(15,23,42,0.16); }
.menu-icon { display:inline-flex; width: 44px; height: 44px; border-radius: 12px; align-items:center; justify-content:center; margin-bottom: 0.6rem; color: white; }
.menu-icon svg { width: 24px; height: 24px; }
.menu-title { display:block; font-size: 1.1rem; letter-spacing: 0.02em; }
.menu-desc { display:block; margin-top: 0.35rem; font-size: 0.9rem; color: #1f2937; font-weight: 600; }
.menu-new .menu-icon { background: var(--menu-new); }
.menu-list .menu-icon { background: var(--menu-list); }
.menu-stats .menu-icon { background: var(--menu-stats); }
.menu-new { border-color: #9a3412; }
.menu-list { border-color: #1e3a8a; }
.menu-stats { border-color: #065f46; }
@media (max-width: 900px) { .menu-grid { grid-template-columns: 1fr; } }

.chart-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.1rem; }
@media (max-width: 980px) { .chart-grid { grid-template-columns: 1fr; } }
.chart-card { position: relative; overflow: hidden; background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%); border: 1px solid rgba(148,163,184,0.35); border-radius: 16px; padding: 1rem; box-shadow: 0 10px 30px rgba(15,23,42,0.08); }
.chart-card::before { content: ""; position: absolute; inset: -40% -20% auto -20%; height: 70%; background: radial-gradient(closest-side, rgba(14,165,233,0.16), rgba(34,197,94,0.08), transparent 70%); pointer-events: none; }
.chart-card::after { content: ""; position: absolute; inset: 0; background: repeating-linear-gradient(135deg, rgba(15,23,42,0.03), rgba(15,23,42,0.03) 8px, transparent 8px, transparent 16px); opacity: 0.35; pointer-events: none; }
.chart-card > * { position: relative; z-index: 1; }
.chart-title { font-weight: 800; letter-spacing: 0.02em; margin: 0 0 0.35rem; }
.chart-sub { color: #475569; margin: 0 0 0.75rem; font-size: 0.85rem; }
.chart-svg { display: block; filter: drop-shadow(0 6px 10px rgba(15,23,42,0.08)); }
.svg-wrap { width: 100%; overflow-x: auto; }
.chart-legend { display:flex; gap: 0.75rem; flex-wrap:wrap; align-items:center; margin-top: 0.6rem; color: #475569; font-size: 0.8rem; }
.legend-item { display:inline-flex; align-items:center; gap:0.35rem; }
.legend-swatch { width: 22px; height: 0; border-top: 3px solid var(--chart-line-start); display:inline-block; border-radius: 999px; }
.legend-line { border-color: var(--chart-line-start); }
.legend-area { border-color: #7dd3fc; box-shadow: inset 0 0 0 6px rgba(125,211,252,0.35); }
.legend-ma { border-color: var(--chart-ma); border-top-style: dashed; }
.legend-trend { border-color: var(--chart-trend); border-top-style: dashed; }
.legend-avg { border-color: var(--chart-avg); border-top-style: dotted; }
.legend-dot { width: 10px; height: 10px; background: var(--chart-line-start); border-radius: 50%; display:inline-block; }
.chart-tooltip { position: fixed; z-index: 50; background: rgba(15,23,42,0.92); color: #e2e8f0; padding: 0.35rem 0.55rem; border-radius: 8px; font-size: 0.8rem; pointer-events: none; opacity: 0; transform: translateY(6px); transition: opacity 120ms ease, transform 120ms ease; box-shadow: 0 8px 18px rgba(15,23,42,0.25); }
.chart-line { filter: drop-shadow(0 3px 8px rgba(14,165,233,0.35)); stroke-dasharray: 2000; stroke-dashoffset: 2000; animation: chart-draw 1.2s ease forwards; }
.chart-area { animation: chart-fade 900ms ease forwards; }
.chart-point { transition: transform 120ms ease, filter 120ms ease; }
.chart-point:hover { transform: scale(1.15); filter: drop-shadow(0 4px 8px rgba(14,165,233,0.5)); }
.chart-point-last { filter: drop-shadow(0 6px 10px rgba(34,197,94,0.45)); }
@keyframes chart-draw { to { stroke-dashoffset: 0; } }
@keyframes chart-fade { from { opacity: 0; } to { opacity: 1; } }
.photo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 0.6rem; margin-top: 0.5rem; }
.photo-grid img { width: 100%; height: 120px; object-fit: cover; border-radius: 10px; border: 1px solid var(--border); background: #fff; }
</style>
</head>
<body>
<header><h1>Tréninkový deník</h1></header>
""");

sb.Append("<div class=\"layout\">");
sb.Append("<nav>");
if (!string.IsNullOrWhiteSpace(username))
{
sb.Append("<a href=\"/\">Rozcestník</a>");
sb.Append("<a href=\"/novy\">Nový záznam</a>");
sb.Append("<a href=\"/zaznamy\">Záznamy</a>");
sb.Append("<a href=\"/statistiky\">Statistiky</a>");
sb.Append("<a href=\"/account\">Účet</a>");
if (isAdmin) sb.Append("<a href=\"/admin/users\">Uživatelé</a>");
sb.Append($"<span class=\"nav-user\">{H(username)}</span>");
sb.Append("<a href=\"/logout\">Odhlásit</a>");
}
else
{
sb.Append("<a href=\"/login\">Přihlášení</a>");
sb.Append("<a href=\"/register\">Registrace</a>");
}
sb.Append("</nav>");

sb.Append("""
<main class="container">
<div class="card">
""");

sb.Append(bodyHtml);

sb.Append("""
</div>
</main>
</div>
</body>
</html>
""");

return sb.ToString();
}

static string SvgLineChart(List<(DateTime x, double y)> points, string title, string unit, bool invertY)
{
static string F(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);

if (points.Count == 0)
{
return $"<p class=\"chart-title\">{H(title)}</p><p class=\"chart-sub\">Žádná data.</p>";
}

// rozměry
const int w = 820;
const int h = 260;
const int padL = 48;
const int padR = 18;
const int padT = 16;
const int padB = 44;

var minX = points.Min(p => p.x);
var maxX = points.Max(p => p.x);
var minY = points.Min(p => p.y);
var maxY = points.Max(p => p.y);

if (Math.Abs(maxY - minY) < 0.000001)
{
maxY = minY + 1;
}

var avgY = points.Average(p => p.y);
var isPace = string.Equals(unit, "min/km", StringComparison.OrdinalIgnoreCase);
string FormatVal(double v) => isPace ? FormatPace(v) : FormatNumber(v);

double X(DateTime dt)
{
var denom = (maxX - minX).TotalDays;
if (denom <= 0) return padL;
var t = (dt - minX).TotalDays / denom;
return padL + t * (w - padL - padR);
}

double Y(double v)
{
// invertY: menší číslo = výš (rychlejší tempo)
var t = (v - minY) / (maxY - minY);
if (invertY) t = 1 - t;
return padT + (1 - t) * (h - padT - padB);
}

var sb = new StringBuilder();
sb.Append($"<p class=\"chart-title\">{H(title)}</p>");
sb.Append($"<p class=\"chart-sub\">{points.Count} bodů - osa Y: {H(unit)}</p>");
sb.Append("<div class=\"svg-wrap\">");
sb.Append($"<svg class=\"chart-svg\" viewBox=\"0 0 {w} {h}\" width=\"100%\" height=\"{h}\" role=\"img\" aria-label=\"{H(title)}\" xmlns=\"http://www.w3.org/2000/svg\">");

// pozadí
sb.Append("<rect x=\"0\" y=\"0\" width=\"100%\" height=\"100%\" fill=\"#ffffff\" />");

var plotW = w - padL - padR;
var plotH = h - padT - padB;

// clip, aby se čára/body nikdy nekreslily mimo plochu grafu
var clipId = "clip-" + Math.Abs(HashCode.Combine(title, points.Count, minX.Ticks, maxX.Ticks, minY, maxY));
var gradId = "grad-" + Math.Abs(HashCode.Combine(title, points.Count, maxX.Ticks));
var areaId = "area-" + Math.Abs(HashCode.Combine(title, points.Count, minX.Ticks));
sb.Append("<defs>");
sb.Append($"<clipPath id=\"{clipId}\"><rect x=\"{padL}\" y=\"{padT}\" width=\"{plotW}\" height=\"{plotH}\" /></clipPath>");
sb.Append($"<linearGradient id=\"{gradId}\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"0\">");
sb.Append("<stop offset=\"0%\" stop-color=\"#0ea5e9\" />");
sb.Append("<stop offset=\"100%\" stop-color=\"#22c55e\" />");
sb.Append("</linearGradient>");
sb.Append($"<linearGradient id=\"{areaId}\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\">");
sb.Append("<stop offset=\"0%\" stop-color=\"#7dd3fc\" stop-opacity=\"0.5\" />");
sb.Append("<stop offset=\"100%\" stop-color=\"#7dd3fc\" stop-opacity=\"0.02\" />");
sb.Append("</linearGradient>");
sb.Append("</defs>");

sb.Append($"<rect x=\"{padL}\" y=\"{padT}\" width=\"{plotW}\" height=\"{plotH}\" fill=\"#f8fafc\" stroke=\"#e2e8f0\" />");

// mřížka
for (var i = 0; i <= 5; i++)
{
var yy = padT + i * plotH / 5.0;
sb.Append($"<line x1=\"{padL}\" y1=\"{F(yy)}\" x2=\"{w - padR}\" y2=\"{F(yy)}\" stroke=\"#e2e8f0\" stroke-width=\"1\" />");
}
for (var i = 0; i <= 4; i++)
{
var xx = padL + i * plotW / 4.0;
sb.Append($"<line x1=\"{F(xx)}\" y1=\"{padT}\" x2=\"{F(xx)}\" y2=\"{h - padB}\" stroke=\"#f1f5f9\" stroke-width=\"1\" />");
}

sb.Append($"<g clip-path=\"url(#{clipId})\">");

// polyline + area
var poly = new StringBuilder();
foreach (var p in points)
{
poly.Append(F(X(p.x)));
poly.Append(',');
poly.Append(F(Y(p.y)));
poly.Append(' ');
}
var polyPoints = poly.ToString().Trim();
var firstPoint = points[0];
var lastPoint = points[^1];
var firstX = F(X(firstPoint.x));
var lastX = F(X(lastPoint.x));
var baseY = F(h - padB);
sb.Append($"<polygon class=\"chart-area\" fill=\"url(#{areaId})\" points=\"{firstX},{baseY} {polyPoints} {lastX},{baseY}\" />");
sb.Append($"<polyline class=\"chart-line\" fill=\"none\" stroke=\"url(#{gradId})\" stroke-width=\"3.5\" stroke-linejoin=\"round\" stroke-linecap=\"round\" points=\"{polyPoints}\" />");

// klouzavý průměr (MA3)
if (points.Count >= 3)
{
var ma = new StringBuilder();
for (var i = 2; i < points.Count; i++)
{
var avg = (points[i - 2].y + points[i - 1].y + points[i].y) / 3.0;
ma.Append(F(X(points[i].x)));
ma.Append(',');
ma.Append(F(Y(avg)));
ma.Append(' ');
}
var maPoints = ma.ToString().Trim();
if (!string.IsNullOrWhiteSpace(maPoints))
{
sb.Append($"<polyline class=\"chart-ma\" fill=\"none\" stroke=\"#16a34a\" stroke-width=\"2\" stroke-linejoin=\"round\" stroke-linecap=\"round\" stroke-dasharray=\"4 4\" points=\"{maPoints}\" />");
}
}

// trend line (lineární regrese)
if (points.Count >= 2)
{
var n = points.Count;
var xs = points.Select(p => (p.x - minX).TotalDays).ToList();
var ys = points.Select(p => p.y).ToList();
var sumX = xs.Sum();
var sumY = ys.Sum();
var sumXY = xs.Zip(ys, (x, y) => x * y).Sum();
var sumX2 = xs.Sum(x => x * x);
var denom = n * sumX2 - sumX * sumX;
if (Math.Abs(denom) > 0.000001)
{
var slope = (n * sumXY - sumX * sumY) / denom;
var intercept = (sumY - slope * sumX) / n;
var yStart = intercept;
var yEnd = intercept + slope * (maxX - minX).TotalDays;
sb.Append($"<line class=\"chart-trend\" x1=\"{padL}\" y1=\"{F(Y(yStart))}\" x2=\"{w - padR}\" y2=\"{F(Y(yEnd))}\" stroke=\"#f59e0b\" stroke-width=\"2\" stroke-dasharray=\"6 4\" opacity=\"0.85\" />");
}
}

// průměrná čára
var avgLineY = F(Y(avgY));
sb.Append($"<line class=\"chart-avg\" x1=\"{padL}\" y1=\"{avgLineY}\" x2=\"{w - padR}\" y2=\"{avgLineY}\" stroke=\"#94a3b8\" stroke-width=\"1\" stroke-dasharray=\"4 4\" opacity=\"0.7\" />");

// body
foreach (var p in points)
{
var cx = X(p.x);
var cy = Y(p.y);
var displayVal = FormatVal(p.y);
sb.Append($"<circle class=\"chart-point\" cx=\"{F(cx)}\" cy=\"{F(cy)}\" r=\"4\" fill=\"#0f172a\" stroke=\"#ffffff\" stroke-width=\"2\" data-date=\"{H(p.x.ToString("dd.MM.yyyy"))}\" data-display=\"{H(displayVal)}\" data-unit=\"{H(unit)}\">");
sb.Append("</circle>");
}

// zvýraznění posledního bodu
var lastCx = F(X(lastPoint.x));
var lastCy = F(Y(lastPoint.y));
sb.Append($"<circle class=\"chart-point chart-point-last\" cx=\"{lastCx}\" cy=\"{lastCy}\" r=\"6\" fill=\"#22c55e\" stroke=\"#ffffff\" stroke-width=\"2\" />");

sb.Append("</g>");

// popisky os (min/max)
sb.Append($"<text x=\"{padL - 8}\" y=\"{padT + 10}\" text-anchor=\"end\" font-size=\"12\" fill=\"#475569\">{H(FormatVal(invertY ? minY : maxY))}</text>");
sb.Append($"<text x=\"{padL - 8}\" y=\"{h - padB}\" text-anchor=\"end\" font-size=\"12\" fill=\"#475569\">{H(FormatVal(invertY ? maxY : minY))}</text>");

sb.Append($"<text x=\"{padL}\" y=\"{h - 16}\" font-size=\"12\" fill=\"#475569\">{H(minX.ToString("dd.MM"))}</text>");
var midX = minX.AddDays((maxX - minX).TotalDays / 2.0);
sb.Append($"<text x=\"{F(X(midX))}\" y=\"{h - 16}\" text-anchor=\"middle\" font-size=\"12\" fill=\"#94a3b8\">{H(midX.ToString("dd.MM"))}</text>");
sb.Append($"<text x=\"{w - padR}\" y=\"{h - 16}\" text-anchor=\"end\" font-size=\"12\" fill=\"#475569\">{H(maxX.ToString("dd.MM"))}</text>");

sb.Append("</svg></div>");
sb.Append("<div class=\"chart-legend\">");
sb.Append("<span class=\"legend-item\"><span class=\"legend-swatch legend-line\"></span>Hodnoty</span>");
sb.Append("<span class=\"legend-item\"><span class=\"legend-swatch legend-area\"></span>Oblast</span>");
sb.Append("<span class=\"legend-item\"><span class=\"legend-swatch legend-ma\"></span>Klouzavý průměr (3)</span>");
sb.Append("<span class=\"legend-item\"><span class=\"legend-swatch legend-trend\"></span>Trend</span>");
sb.Append("<span class=\"legend-item\"><span class=\"legend-swatch legend-avg\"></span>Průměr</span>");
sb.Append("<span class=\"legend-item\"><span class=\"legend-dot\"></span>Poslední bod</span>");
sb.Append("</div>");
return sb.ToString();
}

string BuildCsv(List<TreninkovyZaznam> zaznamy, List<CustomType> customTypes, List<CustomField> customFields, Dictionary<int, Dictionary<int, string>> customValues)
{
var sb = new StringBuilder();
var customTypeById = customTypes.ToDictionary(t => t.Id, t => t.Key);
var customHeaders = new List<string>();
foreach (var f in customFields)
{
if (!customTypeById.TryGetValue(f.TypeId, out var tKey)) continue;
customHeaders.Add($"custom_{tKey}_{f.Key}");
}
var header = "datum,typ,poznamka,tagy,pocasi,cviceni,serie,opakovani,dobaMinuty,vzdalenostKm,tempo,prevyseniM,tep,velikostBazenuM,vzdalenostM,dobaPlavaniMin";
if (customHeaders.Count > 0) header += "," + string.Join(",", customHeaders);
sb.AppendLine(header);
foreach (var z in zaznamy)
{
var row = new[]
{
DateToIso(z.Datum),
z.Typ,
z.Poznamka,
z.Tagy,
z.Pocasi,
z.Cviceni,
z.Serie == 0 ? "" : z.Serie.ToString(CultureInfo.InvariantCulture),
z.Opakovani == 0 ? "" : z.Opakovani.ToString(CultureInfo.InvariantCulture),
z.DobaMinuty == 0 ? "" : z.DobaMinuty.ToString(CultureInfo.InvariantCulture),
z.VzdalenostKm == 0 ? "" : z.VzdalenostKm.ToString("0.##", CultureInfo.InvariantCulture),
z.Tempo,
z.PrevyseniM == 0 ? "" : z.PrevyseniM.ToString(CultureInfo.InvariantCulture),
z.Tep == 0 ? "" : z.Tep.ToString(CultureInfo.InvariantCulture),
z.VelikostBazenuM == 0 ? "" : z.VelikostBazenuM.ToString(CultureInfo.InvariantCulture),
z.VzdalenostM == 0 ? "" : z.VzdalenostM.ToString(CultureInfo.InvariantCulture),
z.DobaPlavaniMin == 0 ? "" : z.DobaPlavaniMin.ToString(CultureInfo.InvariantCulture)
};
var cells = row.ToList();
if (customHeaders.Count > 0)
{
customValues.TryGetValue(z.Id, out var vals);
foreach (var f in customFields)
{
if (!customTypeById.TryGetValue(f.TypeId, out var tKey)) { cells.Add(""); continue; }
if (!string.Equals(z.Typ, tKey, StringComparison.OrdinalIgnoreCase)) { cells.Add(""); continue; }
if (vals is null || !vals.TryGetValue(f.Id, out var v)) { cells.Add(""); continue; }
cells.Add(v ?? "");
}
}
sb.AppendLine(string.Join(",", cells.Select(CsvEscape)));
}
return sb.ToString();
}

static string CsvEscape(string? value)
{
var v = value ?? "";
var needsQuotes = v.Contains(',') || v.Contains('"') || v.Contains('\n') || v.Contains('\r');
if (v.Contains('"')) v = v.Replace("\"", "\"\"");
return needsQuotes ? $"\"{v}\"" : v;
}

static List<string[]> ParseCsvRows(string csv)
{
var rows = new List<string[]>();
var row = new List<string>();
var field = new StringBuilder();
var inQuotes = false;

void EndField()
{
row.Add(field.ToString());
field.Clear();
}

void EndRow()
{
EndField();
rows.Add(row.ToArray());
row = new List<string>();
}

for (var i = 0; i < csv.Length; i++)
{
var c = csv[i];
if (inQuotes)
{
if (c == '"')
{
if (i + 1 < csv.Length && csv[i + 1] == '"')
{
field.Append('"');
i++;
}
else
{
inQuotes = false;
}
}
else
{
field.Append(c);
}
}
else
{
if (c == '"')
{
inQuotes = true;
}
else if (c == ',')
{
EndField();
}
else if (c == '\n')
{
EndRow();
}
else if (c != '\r')
{
field.Append(c);
}
}
}

if (inQuotes)
{
// neukončené uvozovky - bereme zbytek jako pole
inQuotes = false;
}
if (field.Length > 0 || row.Count > 0)
{
EndRow();
}

return rows;
}

static DateTime ParseDateForImport(string? s)
{
var t = (s ?? "").Trim();
if (string.IsNullOrWhiteSpace(t)) return default;
if (DateTime.TryParseExact(t, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var iso)) return iso.Date;
if (DateTime.TryParse(t, CultureInfo.CurrentCulture, DateTimeStyles.None, out var any)) return any.Date;
if (DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.None, out any)) return any.Date;
return default;
}

static int ParseInt(string? s)
{
if (int.TryParse((s ?? "").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)) return v;
if (int.TryParse((s ?? "").Trim(), NumberStyles.Integer, CultureInfo.GetCultureInfo("cs-CZ"), out v)) return v;
return 0;
}

static double ParseDouble(string? s)
{
if (double.TryParse((s ?? "").Trim(), NumberStyles.Any, CultureInfo.InvariantCulture, out var v)) return v;
if (double.TryParse((s ?? "").Trim(), NumberStyles.Any, CultureInfo.GetCultureInfo("cs-CZ"), out v)) return v;
return 0;
}

static int ClampInt(int value, int min, int max)
{
if (value < min) return min;
if (value > max) return max;
return value;
}

static void SplitDistance(double value, out int km, out int dec)
{
if (value <= 0)
{
km = 0;
dec = 0;
return;
}
km = (int)Math.Floor(value);
var frac = value - km;
dec = (int)Math.Round(frac * 10, MidpointRounding.AwayFromZero);
if (dec == 10)
{
km += 1;
dec = 0;
}
km = ClampInt(km, 0, 500);
dec = ClampInt(dec, 0, 9);
}

static (int h, int m, int s) ParseTempoParts(string? tempoText)
{
var t = (tempoText ?? "").Trim();
if (string.IsNullOrWhiteSpace(t)) return (0, 0, 0);
var parts = t.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (parts.Length == 2)
{
if (!int.TryParse(parts[0], out var mm)) return (0, 0, 0);
if (!int.TryParse(parts[1], out var ss)) return (0, 0, 0);
return (0, ClampInt(mm, 0, 59), ClampInt(ss, 0, 59));
}
if (parts.Length == 3)
{
if (!int.TryParse(parts[0], out var hh)) return (0, 0, 0);
if (!int.TryParse(parts[1], out var mm)) return (0, 0, 0);
if (!int.TryParse(parts[2], out var ss)) return (0, 0, 0);
return (ClampInt(hh, 0, 60), ClampInt(mm, 0, 59), ClampInt(ss, 0, 59));
}
return (0, 0, 0);
}

static string BuildTempoFromForm(IFormCollection form, string prefix)
{
var hKey = $"{prefix}_tempo_h";
var mKey = $"{prefix}_tempo_m";
var sKey = $"{prefix}_tempo_s";
if (form.ContainsKey(hKey) || form.ContainsKey(mKey) || form.ContainsKey(sKey))
{
var h = ClampInt(ParseInt(form[hKey].ToString()), 0, 60);
var m = ClampInt(ParseInt(form[mKey].ToString()), 0, 59);
var s = ClampInt(ParseInt(form[sKey].ToString()), 0, 59);
return $"{h}:{m:00}:{s:00}";
}
return form[$"{prefix}_tempo"].ToString();
}

static double BuildDistanceFromForm(IFormCollection form, string prefix)
{
var intKey = $"{prefix}_vzd_int";
var decKey = $"{prefix}_vzd_dec";
if (form.ContainsKey(intKey) || form.ContainsKey(decKey))
{
var km = ClampInt(ParseInt(form[intKey].ToString()), 0, 500);
var dec = ClampInt(ParseInt(form[decKey].ToString()), 0, 9);
return km + (dec / 10.0);
}
return ParseDouble(form[$"{prefix}_vzdalenost"].ToString());
}

static int BuildPrevyseniFromForm(IFormCollection form, string prefix)
{
var kKey = $"{prefix}_prev_k";
var rKey = $"{prefix}_prev_r";
if (form.ContainsKey(kKey) || form.ContainsKey(rKey))
{
var k = ClampInt(ParseInt(form[kKey].ToString()), 0, 100);
var r = ClampInt(ParseInt(form[rKey].ToString()), 0, 999);
var val = (k * 1000) + r;
return ClampInt(val, 0, 100000);
}
return ParseInt(form[$"{prefix}_prevyseni"].ToString());
}

static bool TryParsePaceMinPerKm(string? tempoText, out double paceMinPerKm)
{
paceMinPerKm = 0;
var t = (tempoText ?? "").Trim();
if (string.IsNullOrWhiteSpace(t)) return false;

// povolíme: "5:10", "1:05:30" nebo "5.5" (min)
if (t.Contains(':'))
{
var parts = t.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (parts.Length == 2)
{
if (!int.TryParse(parts[0], out var mm)) return false;
if (!int.TryParse(parts[1], out var ss)) return false;
paceMinPerKm = mm + (ss / 60.0);
return paceMinPerKm > 0;
}
if (parts.Length == 3)
{
if (!int.TryParse(parts[0], out var hh)) return false;
if (!int.TryParse(parts[1], out var mm)) return false;
if (!int.TryParse(parts[2], out var ss)) return false;
paceMinPerKm = (hh * 60) + mm + (ss / 60.0);
return paceMinPerKm > 0;
}
return false;
}

var d = ParseDouble(t);
if (d <= 0) return false;
paceMinPerKm = d;
return true;
}

static string FormatNumber(double v)
{
// pro tempa a obecné hodnoty: max 2 desetinná místa
return v.ToString("0.##", CultureInfo.InvariantCulture);
}

static string FormatPace(double minPerKm)
{
if (minPerKm <= 0) return "-";
var totalSeconds = (int)Math.Round(minPerKm * 60);
var hours = totalSeconds / 3600;
var mins = (totalSeconds / 60) % 60;
var secs = totalSeconds % 60;
if (hours > 0) return $"{hours}:{mins:00}:{secs:00}";
return $"{mins}:{secs:00}";
}

static string H(string? s)
{
// mini HTML escape
if (string.IsNullOrEmpty(s)) return "";
return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");
}

record User
{
public int Id { get; set; }
public string Username { get; set; } = string.Empty;
public bool IsAdmin { get; set; }
}

record UserInfo
{
public int Id { get; set; }
public string Username { get; set; } = string.Empty;
public bool IsAdmin { get; set; }
public string CreatedAt { get; set; } = string.Empty;
}

record LoginRequest
{
public string? Username { get; set; }
public string? Password { get; set; }
}

record RegisterRequest
{
public string? Username { get; set; }
public string? Password { get; set; }
public string? Password2 { get; set; }
}

record ApiRecord
{
public int Id { get; set; }
public string Datum { get; set; } = "";
public string Typ { get; set; } = "";
public string? Poznamka { get; set; }
public string? Pocasi { get; set; }
public string[] Tagy { get; set; } = Array.Empty<string>();
public bool IsPublic { get; set; }
public double VzdalenostKm { get; set; }
public string? Tempo { get; set; }
public int PrevyseniM { get; set; }
public int Tep { get; set; }

public int VelikostBazenuM { get; set; }
public int VzdalenostM { get; set; }
public int DobaPlavaniMin { get; set; }

public string? Cviceni { get; set; }
public int Serie { get; set; }
public int Opakovani { get; set; }
public int DobaMinuty { get; set; }
}

record ApiRecordInput
{
public string? Datum { get; set; }
public string? Typ { get; set; }
public string? Poznamka { get; set; }
public string? Pocasi { get; set; }
public string[]? Tagy { get; set; }
public bool? IsPublic { get; set; }

public double? VzdalenostKm { get; set; }
public string? Tempo { get; set; }
public int? PrevyseniM { get; set; }
public int? Tep { get; set; }

public int? VelikostBazenuM { get; set; }
public int? VzdalenostM { get; set; }
public int? DobaPlavaniMin { get; set; }

public string? Cviceni { get; set; }
public int? Serie { get; set; }
public int? Opakovani { get; set; }
public int? DobaMinuty { get; set; }
}

record TreninkovyZaznam
{
public int Id { get; set; }
public DateTime Datum { get; set; }
public string Typ { get; set; } = "cviceni"; // beh, kolo, turistika, cviceni, plavani

public string Poznamka { get; set; } = string.Empty;
public string Tagy { get; set; } = string.Empty;
public string Pocasi { get; set; } = string.Empty;
public int UserId { get; set; }
public bool IsPublic { get; set; }

// Cvičení / doba aktivity
public string Cviceni { get; set; } = string.Empty;
public int Serie { get; set; }
public int Opakovani { get; set; }
public int DobaMinuty { get; set; }

// Běh
public double VzdalenostKm { get; set; }
public string Tempo { get; set; } = string.Empty;
public int PrevyseniM { get; set; }
public int Tep { get; set; }

// Plavání
public int VelikostBazenuM { get; set; }
public int VzdalenostM { get; set; }
public int DobaPlavaniMin { get; set; }
}

record TreninkFoto
{
public int Id { get; set; }
public int TreninkId { get; set; }
public int UserId { get; set; }
public string FileName { get; set; } = string.Empty;
public string OriginalName { get; set; } = string.Empty;
public string ContentType { get; set; } = "image/jpeg";
public string CreatedAt { get; set; } = string.Empty;
}

record CustomType
{
public int Id { get; set; }
public int UserId { get; set; }
public string Key { get; set; } = string.Empty;
public string Name { get; set; } = string.Empty;
public string CreatedAt { get; set; } = string.Empty;
}

record CustomField
{
public int Id { get; set; }
public int TypeId { get; set; }
public string Key { get; set; } = string.Empty;
public string Label { get; set; } = string.Empty;
public string DataType { get; set; } = "text"; // text, number, bool
public string? Unit { get; set; }
public double? MinValue { get; set; }
public double? MaxValue { get; set; }
public int SortOrder { get; set; }
}













