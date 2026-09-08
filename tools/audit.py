import argparse, ipaddress, json, os, random, re, subprocess, sys, tarfile, time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mmdb import MMDB

BASE     = os.path.dirname(os.path.abspath(__file__))
STATE    = os.path.join(BASE, "state.json")
REPO     = os.path.join(BASE, "repo")
GEODB    = os.path.join(BASE, "GeoLite2-Country.mmdb")
MMCONF   = os.path.join(BASE, "maxmind.conf")
CONF     = os.path.join(BASE, "audit.conf")
UPSTREAM = "/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml"
GEOSITE  = "/v2fly/domain-list-community/master/data/"
GEOSITE_ROOT = "cn"
MMURL    = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
GEO_MAXAGE = 3 * 86400
OVERRIDES  = os.path.join(BASE, "overrides.txt")
CIDROVR    = os.path.join(BASE, "cidr_overrides.txt")
MAX_DRIFT  = 0.05
GEO_STALE  = 30 * 86400

CANARY = {"223.5.5.5": True, "114.114.114.114": True, "180.163.117.53": True,
          "8.8.8.8": False, "1.1.1.1": False, "47.76.127.217": False}

RESOLVERS = ["223.5.5.5", "119.29.29.29"]
WORKERS   = 120
FAIL_MAX  = 7
ROTATE    = 30

def read_conf(path):
    d = {}
    if os.path.exists(path):
        for ln in open(path):
            ln = ln.split("#")[0].strip()
            if "=" in ln:
                k, v = ln.split("=", 1)
                d[k.strip()] = v.strip()
    return d

CFG       = read_conf(CONF)
PROXY_H   = CFG.get("proxy_host") or ""
PROXY_IP  = CFG.get("proxy_ip") or ""
GIT_REMOTE = CFG.get("git_remote") or ""
GIT_NAME   = CFG.get("git_name") or ""
GIT_EMAIL  = CFG.get("git_email") or ""
RAW_BASE   = CFG.get("raw_base") or "https://raw.githubusercontent.com"
if CFG.get("resolvers"):
    RESOLVERS = [x.strip() for x in CFG["resolvers"].split(",") if x.strip()]

def log(m):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {m}", flush=True)

def fetch(path):
    if PROXY_H:
        cmd = ["curl", "-fsSL", "--max-time", "120"]
        if PROXY_IP:
            cmd += ["--resolve", f"{PROXY_H}:443:{PROXY_IP}"]
        cmd.append(f"https://{PROXY_H}{path}")
    else:
        cmd = ["curl", "-fsSL", "--max-time", "120",
               f"https://raw.githubusercontent.com{path}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"下载失败 {path}: {r.stderr.strip()[:200]}")
    return r.stdout

def refresh_geodb():

    if os.path.exists(GEODB) and time.time() - os.path.getmtime(GEODB) < GEO_MAXAGE:
        return
    if not os.path.exists(MMCONF):
        raise SystemExit(f"缺少 {MMCONF}（需含 AccountID / LicenseKey）")
    conf = {}
    for line in open(MMCONF):
        p = line.split()
        if len(p) >= 2 and not line.startswith("#"):
            conf[p[0]] = p[1]
    acct, key = conf.get("AccountID"), conf.get("LicenseKey")
    if not (acct and key):
        raise SystemExit(f"{MMCONF} 里缺 AccountID 或 LicenseKey")
    tgz = GEODB + ".tar.gz"
    cfg = "\n".join([f'user = "{acct}:{key}"', "silent", "show-error", "location",
                     "max-time = 300", f'output = "{tgz}"', f'url = "{MMURL}"'])
    r = subprocess.run(["curl", "-K", "-"], input=cfg, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(tgz):
        raise SystemExit(f"MaxMind 下载失败: {r.stderr.strip()[:200]}")
    with tarfile.open(tgz) as t:
        m = next((x for x in t.getmembers() if x.name.endswith("GeoLite2-Country.mmdb")), None)
        if m is None:
            raise SystemExit("压缩包里没有 GeoLite2-Country.mmdb")
        m.name = os.path.basename(m.name)
        t.extract(m, BASE, filter="data")
    os.remove(tgz)

    os.utime(GEODB, None)
    log(f"MaxMind 库已更新（{os.path.getsize(GEODB)/1e6:.1f} MB）")

class Geo:

    def __init__(self, mm, path):
        self.mm = mm
        self.deny, self.allow = [], []
        if os.path.exists(path):
            for ln in open(path):
                ln = ln.split("#")[0].strip()
                if not ln:
                    continue
                p = ln.split()
                if len(p) != 2:
                    continue
                try:
                    n = ipaddress.ip_network(p[1], strict=False)
                except ValueError:
                    continue
                if n.version != 4:
                    continue
                pair = (int(n.network_address), int(n.broadcast_address))
                if p[0].lower() == "notcn":
                    self.deny.append(pair)
                elif p[0].lower() == "cn":
                    self.allow.append(pair)
        self.meta = mm.meta

    def is_cn(self, ip):
        try:
            a = int(ipaddress.ip_address(ip))
        except ValueError:
            return False
        for lo, hi in self.deny:
            if lo <= a <= hi:
                return False
        for lo, hi in self.allow:
            if lo <= a <= hi:
                return True
        return self.mm.is_cn(ip)

    @property
    def overrides(self):
        return len(self.deny), len(self.allow)

def verify_geodb(geo):

    n = geo.meta.get("node_count", 0)
    if n < 1_000_000:
        raise SystemExit(f"中止：GeoLite2 节点数只有 {n:,}，疑似库损坏或被换成精简库")
    age = time.time() - geo.meta.get("build_epoch", 0)
    if age > GEO_STALE:
        raise SystemExit(f"中止：GeoLite2 构建于 {age/86400:.0f} 天前，过旧")
    bad = [f"{ip}(判 {geo.is_cn(ip)}，应为 {want})"
           for ip, want in CANARY.items() if geo.is_cn(ip) != want]
    if bad:
        raise SystemExit("中止：GeoIP 金丝雀校验失败 —— " + "；".join(bad))

def load_overrides():

    drop, keep = set(), set()
    if not os.path.exists(OVERRIDES):
        return drop, keep
    for ln in open(OVERRIDES):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        p = ln.split(None, 1)
        if len(p) != 2:
            continue
        act, ent = p[0].lower(), p[1].strip()
        if act == "drop":
            drop.add(ent)
        elif act == "keep":
            keep.add(ent)
    return drop, keep

def previous_count():

    p = os.path.join(REPO, "yaml", "ChinaMax_Domain.yaml")
    if not os.path.exists(p):
        return 0
    return sum(1 for l in open(p) if l.startswith("  - "))

def load_geosite(root=GEOSITE_ROOT):

    seen, out, level = set(), set(), [root]
    while level:
        level = [n for n in dict.fromkeys(level) if n not in seen]
        if not level:
            break
        seen.update(level)
        with ThreadPoolExecutor(min(24, len(level))) as ex:
            texts = list(ex.map(lambda n: _geosite_fetch(n), level))
        nxt = []
        for text in texts:
            for ln in text.splitlines():
                ln = ln.split("#")[0].strip()
                if not ln:
                    continue
                body = ln.split()[0]
                if body.startswith("include:"):
                    nxt.append(body[8:].strip())
                elif body.startswith("full:"):
                    out.add(body[5:].strip().lower())
                elif body.startswith(("keyword:", "regexp:")):
                    continue
                elif body.startswith("domain:"):
                    out.add("+." + body[7:].strip().lower())
                else:
                    out.add("+." + body.strip().lower())
        level = nxt
    return seen, out

def _geosite_fetch(name):
    try:
        return fetch(GEOSITE + name)
    except SystemExit:
        return ""

def dedupe(entries):

    suffixes = {e[2:] for e in entries if e.startswith("+.")}
    keep = []
    for e in entries:
        h = e[2:] if e.startswith("+.") else e
        parts = h.split(".")
        covered = False
        start = 1 if e.startswith("+.") else 0
        for i in range(start, len(parts)):
            if ".".join(parts[i:]) in suffixes:
                covered = True
                break
        if not covered:
            keep.append(e)
    return sorted(set(keep))

def hostname(entry):

    e = entry.strip().strip("'\"")
    for p in ("+.", "*.", "."):
        if e.startswith(p):
            return e[len(p):]
    return e

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def is_ipv4(s):

    if not _IPV4_RE.match(s):
        return False
    return all(int(o) < 256 for o in s.split("."))

def dig(server, name):
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", f"@{server}", name, "A"],
            capture_output=True, text=True, timeout=6)
        return [l for l in (x.strip() for x in r.stdout.splitlines()) if is_ipv4(l)]
    except Exception:
        return []

def resolve(entry, geo):

    host = hostname(entry)
    out = []
    for name in (host, "www." + host):
        for s in random.sample(RESOLVERS, len(RESOLVERS)):
            ips = dig(s, name)
            if ips:
                out.extend(ips)
                if any(geo.is_cn(i) for i in ips):
                    return entry, sorted(set(out))
                break
    return entry, sorted(set(out))

def verdict(ips, geo):
    if not ips:
        return "nx"
    return "cn" if any(geo.is_cn(i) for i in ips) else "foreign"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-push", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true", help="跳过发布差分护栏")
    ap.add_argument("--reclassify", action="store_true",
                    help="不发起 DNS，用 state 里存的 IP 重算判定（判据或覆盖表变更后用）")
    a = ap.parse_args()

    log("准备 MaxMind 库…")
    refresh_geodb()
    mm = MMDB(GEODB)
    geo = Geo(mm, CIDROVR)
    built = datetime.fromtimestamp(mm.meta["build_epoch"], timezone.utc).strftime("%Y-%m-%d")
    verify_geodb(mm)
    nd, na = geo.overrides
    log(f"GeoLite2-Country 构建于 {built}，节点 {mm.meta['node_count']:,}（自检通过）"
        + (f"；人工 CIDR 覆盖 {nd} 段非大陆 / {na} 段大陆" if nd or na else ""))

    log("下载上游列表…")
    raw = []
    for l in fetch(UPSTREAM).splitlines():
        x = l.strip()
        if x.startswith("- ") and not x.startswith("#"):
            raw.append(x[2:].strip().strip("'\""))
    n_cm = len(set(raw))
    files, gs = load_geosite()
    raw += sorted(gs)
    log(f"上游 ChinaMax {n_cm} 条 + geosite:cn {len(gs)} 条（展开 {len(files)} 个文件）")
    entries = sorted(set(e for e in raw if e))
    log(f"合并后 {len(entries)} 条（去重在审计之后做——先剔除会让被覆盖的子域"
        f"失去单独审计的机会，而父域可能判为境外、子域却在大陆）")

    state = {}
    if os.path.exists(STATE):
        with open(STATE) as f:
            state = json.load(f)

    today = date.today().isoformat()
    known = set(state)
    new_e = [e for e in entries if e not in known]

    if a.reclassify:
        batch = [e for e in entries if state.get(e, {}).get("ips")]
    elif a.full:
        batch = entries
    else:
        idx = date.today().toordinal() % ROTATE
        rot = [e for i, e in enumerate(sorted(known & set(entries))) if i % ROTATE == idx]
        batch = new_e + rot
    if a.limit:
        batch = batch[:a.limit]
    log(f"本轮审计 {len(batch)} 条（新增 {len(new_e)}）")

    if a.reclassify:
        resolved = [(e, state[e]["ips"]) for e in batch]
        log(f"重算判定 {len(batch)} 条（复用已存 IP，不发起 DNS）")
    else:
        t0 = time.time()
        with ThreadPoolExecutor(WORKERS) as ex:
            resolved = list(ex.map(lambda e: resolve(e, geo), batch))
        log(f"解析完成，用时 {time.time()-t0:.0f}s")

    results = [(e, verdict(ips, geo), ips) for e, ips in resolved]

    rate = sum(1 for _, v, _ in results if v == "cn") / max(len(results), 1)
    if not a.limit and len(results) >= 200 and rate < 0.40:
        raise SystemExit(f"中止：本轮 CN 判定率仅 {rate:.0%}（正常约 70%），"
                         f"疑似解析器异常，不更新状态")

    stat = {"cn": 0, "foreign": 0, "nx": 0}
    for e, v, ips in results:
        stat[v] += 1
        rec = state.setdefault(e, {"cn": None, "fail": 0})
        if v == "cn":
            rec["cn"] = today
            rec["fail"] = 0
        else:
            rec["fail"] = rec.get("fail", 0) + 1
            if a.reclassify:

                rec["cn"] = None
        rec["last"] = today
        rec["why"] = v
        rec["ips"] = ips[:6]
    for e in list(state):
        if e not in entries:
            del state[e]
    log(f"本轮结果 CN {stat['cn']} / 境外 {stat['foreign']} / 无解析 {stat['nx']}")

    od, ok_ = load_overrides()
    keep = [e for e in entries
            if (e in ok_) or
               (e not in od and state.get(e, {}).get("cn")
                and state[e].get("fail", 0) < FAIL_MAX)]
    if od or ok_:
        log(f"人工覆盖：强制剔除 {len(od & set(entries))} 条，强制保留 {len(ok_ & set(entries))} 条")
    n_raw = len(keep)
    keep = dedupe(keep)
    log(f"保留 {n_raw} / {len(entries)}；后缀去重 -> {len(keep)} 条"
        f"（冗余 {n_raw-len(keep)}）")

    prev = previous_count()
    if prev and not a.force and not a.limit:
        drift = abs(len(keep) - prev) / prev
        if drift > MAX_DRIFT:
            raise SystemExit(
                f"中止：保留条数从 {prev:,} 变为 {len(keep):,}（{drift*100:.1f}%），"
                f"超过 {MAX_DRIFT*100:.0f}% 阈值。上游剧变、解析器故障或 GeoIP 异常都会长这样。"
                f"\n人工确认无误后加 --force 重跑。旧文件未被覆盖。")

    if not a.dry_run:
        write_outputs(keep, entries, state, built)
        if not a.no_push:
            publish(len(keep), len(entries))
    with open(STATE, "w") as f:
        json.dump(state, f, separators=(",", ":"))
    log("完成")

def strip_comments(src):

    import io, tokenize
    out, prev_end, prev_tok = [], (1, 0), tokenize.INDENT
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        ttype, tstr, start, end, _ = tok
        if start[0] > prev_end[0]:
            prev_end = (start[0], 0)
        if ttype == tokenize.COMMENT:
            prev_end = end
            continue
        if ttype == tokenize.STRING and prev_tok in (
                tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT, None):
            prev_end = end
            prev_tok = ttype
            continue
        if start[0] > prev_end[0]:
            out.append("\n" * (start[0] - prev_end[0]))
        elif start[1] > prev_end[1]:
            out.append(" " * (start[1] - prev_end[1]))
        out.append(tstr)
        prev_end = end
        if ttype not in (tokenize.NL, tokenize.COMMENT):
            prev_tok = ttype
    txt = "".join(out)
    lines, res, blank = txt.splitlines(), [], 0
    for l in lines:
        if l.strip():
            blank = 0
            res.append(l.rstrip())
        else:
            blank += 1
            if blank <= 1:
                res.append("")
    return "\n".join(res).strip() + "\n"

def copy_tools():
    d = os.path.join(REPO, "tools")
    os.makedirs(d, exist_ok=True)
    for name in ("audit.py", "mmdb.py"):
        src = os.path.join(BASE, name)
        if not os.path.exists(src):
            continue
        with open(os.path.join(d, name), "w") as f:
            f.write(strip_comments(open(src).read()))
    with open(os.path.join(d, "audit.conf.example"), "w") as f:
        f.write("proxy_host =\n"
                "proxy_ip   =\n"
                "resolvers  = 223.5.5.5, 119.29.29.29\n"
                "git_remote =\n"
                "git_name   =\n"
                "git_email  =\n"
                "raw_base   = https://raw.githubusercontent.com\n")

def write_outputs(keep, entries, state, built):
    os.makedirs(os.path.join(REPO, "yaml"), exist_ok=True)
    os.makedirs(os.path.join(REPO, "list"), exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hdr = (f"# ChinaMax_Fixed —— 经国内 DNS 实测校验的中国大陆域名集合\n"
           f"# 上游 blackmatrix7/ios_rule_script ChinaMax_Domain\n"
           f"# 判据 国内解析器解出的 A 记录在 MaxMind GeoLite2 中 country=CN（不含 HK/MO/TW）\n"
           f"# GeoLite2 构建于 {built}\n"
           f"# 生成 {ts}\n"
           f"# 上游 {len(entries)} 条 → 保留 {len(keep)} 条\n")

    with open(os.path.join(REPO, "yaml", "ChinaMax_Domain.yaml"), "w") as f:
        f.write(hdr + "\npayload:\n")
        for e in keep:
            f.write(f"  - '{e}'\n")

    with open(os.path.join(REPO, "list", "ChinaMax_Domain.list"), "w") as f:
        f.write(hdr + "\n")
        for e in keep:
            h = e[2:] if e.startswith("+.") else e
            f.write(("." + h if e.startswith("+.") else h) + "\n")

    copy_tools()

    slug = ""
    if GIT_REMOTE:
        slug = GIT_REMOTE.split(":")[-1].removesuffix(".git")
    base = f"{RAW_BASE}/{slug}/main" if slug else "<raw base>"
    drop = len(entries) - len(keep)
    with open(os.path.join(REPO, "README.md"), "w") as f:
        f.write(f"""# china_max_fixed

合并两个上游域名集合、经国内 DNS 实测校验后的中国大陆直连列表，每日更新。

## 为什么需要这个

常见的中国大陆直连域名列表几乎都源自 `dnsmasq-china-list`，
它的收录标准是「域名有大陆 NS 服务器」。

问题在于，用阿里云、腾讯云国际站建站的**境外网站**同样会被分到大陆 NS，
于是大量并非中国大陆的域名混进了这份列表
（参见 [blackmatrix7/ios_rule_script#1615](https://github.com/blackmatrix7/ios_rule_script/issues/1615)）。

把它们放进直连列表有两个后果：访问这些站点时**不走代理**，
以及**DNS 查询暴露**。对按域名分流的配置来说，这是静默失效。

本项目合并两个上游共 {len(entries):,} 条逐条实测，其中 {drop:,} 条（{drop/max(len(entries),1)*100:.1f}%）
解析不到中国大陆 IP。

上游有两个：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 的
ChinaMax 覆盖广但机器生成，[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
的 `geosite:cn` 经人工审核但只有八千余条。两者取并集再统一过判据，
覆盖率与准确性都比单用其一更好。

## 脚本做了什么

从位于中国大陆的服务器出发，每日执行：

1. 拉取两个上游列表并合并（`geosite:cn` 需递归展开其 `include:` 引用）
2. 用国内解析器查询每个域名及其 `www.` 变体的 A 记录
3. 判断 A 记录是否落在中国大陆 —— 依据 MaxMind GeoLite2-Country 官方库的
   `country.iso_code == "CN"`。港澳台代码独立（`HK` / `MO` / `TW`），因此被排除：
   从大陆直连港澳机房既不快，也不应按境内处理
4. 只保留判定为大陆的域名，剔除被后缀覆盖的冗余项，生成两种格式并推送

去重放在判定**之后**：若先去重，`+.example.com` 会覆盖掉
`+.cdn.example.com`，而前者可能解析到境外、后者却在大陆，
这条合法条目就会既无机会单独判定、又随父域一起被剔除。

脚本**只做剔除，不做添加**，输出必定是上游的子集。
误剔一个域名的后果是它走代理（慢但可用）。
连续 {FAIL_MAX} 次判定失败才真正剔除，避免地理 DNS 的随机性造成误删。
全量条目在 {ROTATE} 天内至少复核一次。

判定错误无法完全避免 —— 只要 GeoIP 把某个 IP 标成 CN，
该域名就会留在直连表里。`cidr_overrides.txt` 用于人工纠正已确认的个案。

## 当前状态

| | |
| --- | --- |
| 上游条目 | {len(entries):,} |
| 保留 | {len(keep):,} |
| 剔除 | {drop:,}（{drop/max(len(entries),1)*100:.1f}%） |
| GeoLite2 构建于 | {built} |
| 更新于 | {ts} |

## 用法

两种格式内容相同，按需取用。

**YAML**（`behavior: domain` 规则集）

```
{base}/yaml/ChinaMax_Domain.yaml
```

```yaml
rule-providers:
  China_Domain:
    type: http
    behavior: domain
    format: yaml
    interval: 86400
    url: '{base}/yaml/ChinaMax_Domain.yaml'
    path: './RuleSet/ChinaMax_Domain.yaml'
```

**纯文本列表**（每行一个域名，前导 `.` 表示含子域名）

```
{base}/list/ChinaMax_Domain.list
```

```
DOMAIN-SET,{base}/list/ChinaMax_Domain.list,DIRECT
```

## 自行部署

脚本在 [`tools/`](tools/)，只依赖 Python 3 标准库与 `dig`、`curl`。
复制 `audit.conf.example` 为 `audit.conf` 并填写，
`maxmind.conf` 填入 MaxMind 账号（`AccountID` / `LicenseKey`），然后：

```
python3 audit.py --full     # 全量
python3 audit.py            # 每日增量
```

需要在**中国大陆**的机器上运行，判据依赖国内解析器的解析结果。

## 许可

规则数据来自上游 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)。
脚本以 MIT 发布。
GeoLite2 数据由 MaxMind 提供（[GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula)）。
""")

def git(*args, check=True):
    return subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True,
                          check=check)

def publish(keep_n, total_n):
    env_key = os.path.join(BASE, "deploy_key")
    ssh = f"ssh -i {env_key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"
    if not GIT_REMOTE:
        log("未配置 git_remote，跳过推送")
        return
    if not os.path.isdir(os.path.join(REPO, ".git")):
        git("init", "-q", "-b", "main")
        git("remote", "add", "origin", GIT_REMOTE)
    git("remote", "set-url", "origin", GIT_REMOTE)
    if GIT_NAME:
        git("config", "user.name", GIT_NAME)
    if GIT_EMAIL:
        git("config", "user.email", GIT_EMAIL)
    git("config", "core.sshCommand", ssh)
    git("add", "-A")
    if not git("diff", "--cached", "--quiet", check=False).returncode:
        log("无变化，跳过提交")
        return
    msg = (f"更新规则集：保留 {keep_n:,} / {total_n:,}\n\n"
           f"由 audit.py 每日自动生成。\n\n"
           f"Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>")
    git("commit", "-q", "-m", msg)
    r = git("push", "-u", "origin", "main", check=False)
    if r.returncode:
        raise SystemExit(f"推送失败: {r.stderr.strip()[:300]}")
    log("已推送到 GitHub")

if __name__ == "__main__":
    main()
