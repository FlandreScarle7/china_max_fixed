#!/usr/bin/env python3
"""
ChinaMax 域名列表审计

判据：从国内解析器能解析出**中国大陆** IP 的域名，才保留在直连列表里。

「是不是大陆 IP」用 MaxMind GeoLite2-Country 官方库判定，只认
country.iso_code == "CN"。港澳台各有自己的代码（HK / MO / TW），
因此天然被排除 —— 港澳机房虽然常被国内清单算作「中国」，
但从大陆直连它们既不快也不该当作境内处理。

两个必须避开的坑：

  * 绝不能回退到 registered_country。腾讯云新加坡的 43.109.70.194
    country=HK 而 registered_country=SG，阿里云香港 47.76.127.217
    country=HK 而 registered_country=US —— 按注册国判会全乱。

  * 不要用 Hackl0us/GeoIP2-CN 或 17mon/china_ip_list。后者是 ipip.net
    的免费库，其 README 自述「每季度更新一次」「为减少条目数量……
    做模糊化处理」；前者由它派生。实测把 43.0.0.0/10 整块当成中国，
    而那是腾讯云新加坡实体（ASEPL-SG / ACEVILLEPTELTD-SG）。
    7.4 万个真实 IP 上与 MaxMind 有 651 处分歧，抽样用 APNIC 注册记录
    仲裁，两个方向 MaxMind 都以 31:9 胜出。

用法：
  audit.py            增量（上游新增 + 1/30 轮换复核）
  audit.py --full     全量复核
  audit.py --dry-run  只审计，不写输出、不推送
  audit.py --no-push  写输出但不推送
  audit.py --limit N  只审计前 N 条，用于验证改动
"""
import argparse, ipaddress, json, os, random, re, subprocess, sys, tarfile, time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mmdb import MMDB

BASE     = os.path.dirname(os.path.abspath(__file__))
STATE    = os.path.join(BASE, "state.json")
REPO     = BASE
GEODB    = os.path.join(BASE, "GeoLite2-Country.mmdb")
MMCONF   = os.path.join(BASE, "maxmind.conf")     # 权限 600，绝不进仓库
CONF     = os.path.join(BASE, "audit.conf")
UPSTREAM = "/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml"
GEOSITE  = "/v2fly/domain-list-community/master/data/"
GEOSITE_ROOT = "cn"
MMURL    = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
GEO_MAXAGE = 3 * 86400        # MaxMind 每周二、五更新，三天一拉足够
OVERRIDES  = os.path.join(BASE, "overrides.txt")        # 域名级
CIDROVR    = os.path.join(BASE, "cidr_overrides.txt")  # IP 段级，纠正 GeoIP 判错
MAX_DRIFT  = 0.05             # 与上次发布相比，保留条数变动超过这个比例就中止
GEO_STALE  = 30 * 86400       # GeoLite2 构建时间超过这个就认为不可信

# 金丝雀：库一旦损坏、截断，或 mmdb 解析器出 bug，这组断言会先炸，
# 而不是让 11 万条域名按错误判定发布出去。
CANARY = {"223.5.5.5": True, "114.114.114.114": True, "180.163.117.53": True,
          "8.8.8.8": False, "1.1.1.1": False, "47.76.127.217": False}

# 实测：500 条样本下任意两路解析器组合即达到全部五路的判定覆盖。
# 保留腾讯云 VPC 内网解析器（最快、不限流）+ 阿里公共（独立运营商）。
RESOLVERS = ["223.5.5.5", "119.29.29.29"]
WORKERS   = 120
FAIL_MAX  = 7      # 连续失败多少天后剔除
ROTATE    = 30     # 增量模式下每天复核 1/30

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
PROXY_H   = os.environ.get("PROXY_HOST") or CFG.get("proxy_host") or "ghraw.flandre.vip"
PROXY_IP  = os.environ.get("PROXY_IP") or CFG.get("proxy_ip") or "3.1.208.104"
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
    """按需从 MaxMind 官方拉库。凭据只经 curl -K 的 stdin，不出现在命令行/ps 里。"""
    if os.path.exists(GEODB) and time.time() - os.path.getmtime(GEODB) < GEO_MAXAGE:
        return
    conf = {}
    if os.path.exists(MMCONF):
        for line in open(MMCONF):
            p = line.split()
            if len(p) >= 2 and not line.startswith("#"):
                conf[p[0]] = p[1]
    acct = os.environ.get("MAXMIND_ACCOUNT_ID") or conf.get("AccountID")
    key = os.environ.get("MAXMIND_LICENSE_KEY") or conf.get("LicenseKey")
    if not (acct and key):
        raise SystemExit("缺少 MaxMind 凭据（需设置 MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY 环境变量或配置 maxmind.conf）")
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
    # tar 会保留归档内的 mtime（即 MaxMind 的构建日期），
    # 不重置的话新鲜度判断永远认为过期，每次运行都会重下 8.6 MB。
    os.utime(GEODB, None)
    log(f"MaxMind 库已更新（{os.path.getsize(GEODB)/1e6:.1f} MB）")

class Geo:
    """MaxMind 判定，叠加人工 CIDR 覆盖。

    GeoIP 库出错是常态而非例外 —— 例如 MaxMind 把 202.95.0.0/19
    （RACKIP CONSULTANCY PTE. LTD.）标为 CN，而从上海实测 212ms
    且经联通国际出口，客观上不在大陆。这类个案不该逼着改判据，
    在 cidr_overrides.txt 里钉一行即可。

    格式：  notcn 202.95.0.0/19      # 强制判为非大陆
            cn    219.234.16.0/20    # 强制判为大陆
    """
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
        for lo, hi in self.deny:          # 否决优先，安全方向
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
    """上线前自检，任何一项不过就中止，绝不用可疑的库去判定。"""
    n = geo.meta.get("node_count", 0)
    if n < 400_000:  # MaxMind 2024+ 优化后 Country 树节点约 54~60 万
        raise SystemExit(f"中止：GeoLite2 节点数只有 {n:,}，疑似库损坏或被换成精简库")
    age = time.time() - geo.meta.get("build_epoch", 0)
    if age > GEO_STALE:
        raise SystemExit(f"中止：GeoLite2 构建于 {age/86400:.0f} 天前，过旧")
    bad = [f"{ip}(判 {geo.is_cn(ip)}，应为 {want})"
           for ip, want in CANARY.items() if geo.is_cn(ip) != want]
    if bad:
        raise SystemExit("中止：GeoIP 金丝雀校验失败 —— " + "；".join(bad))

def load_overrides():
    """人工覆盖表。每行 `drop <条目>` 或 `keep <条目>`，# 开头为注释。

    用于钉死已查实的判定错误（例如 MaxMind 把 202.95.0.0/19 标成 CN，
    实测从上海 212ms、经联通国际出口，根本不在大陆），
    不必为个别条目去动判据。
    """
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
    """上次发布的保留条数，取自仓库里的 clash 输出。"""
    p = os.path.join(REPO, "yaml", "ChinaMax_Domain.yaml")
    if not os.path.exists(p):
        return 0
    return sum(1 for l in open(p) if l.startswith("  - "))

def load_geosite(root=GEOSITE_ROOT):
    """递归展开 v2fly 的 geosite 数据文件。

    v2fly 按「一个组织/类别一个文件」组织，cn 展开后有三百多个文件，
    其中近百个只有个位数条目、几十个是纯 include 中转。逐个串行拉取
    要三分钟，所以按层并发——同一层的文件互不依赖，可以一起取。

    条目形如 domain:x / full:x / keyword:x / regexp:x，后面可跟 @attr；
    include 行同样可能带属性（include:eastmoney @-!cn），因此一律先按
    空白切分再取第一段。keyword 与 regexp 无法表达为 domain 规则，丢弃；
    属性不做预筛，去留交给解析判据。
    """
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
    """剔除被后缀条目覆盖的冗余项。

    +.example.com 存在时，+.a.example.com 与 a.example.com 都是多余的。
    """
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
    """把规则条目还原成可解析的主机名"""
    e = entry.strip().strip("'\"")
    for p in ("+.", "*.", "."):
        if e.startswith(p):
            return e[len(p):]
    return e

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def is_ipv4(s):
    """dig +short 会先打印 CNAME 链；形如 132.youboy.net. 的名字同样满足
    "首字符是数字且有三个点"，所以必须真正校验成 IPv4 才能算解析结果。"""
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
    """返回该域名（含 www. 变体）在国内解析器上拿到的全部 A 记录。

    apex 与 www 都要查 —— 例如 jpmorganchina.com 的 apex 在摩根自己的
    境外 AS，而 www 落在上海电信，只查 apex 会误判为境外。
    一旦拿到大陆 IP 就提前收工，省掉 www 那一轮。
    """
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
    verify_geodb(mm)                 # 金丝雀校验底层库本身，不受人工覆盖影响
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
                # 判据/覆盖表变更是确定性结论，不是 DNS 抖动，
                # 不该再走 FAIL_MAX 的缓冲，立即失去保留资格。
                rec["cn"] = None
        rec["last"] = today
        rec["why"] = v
        rec["ips"] = ips[:6]        # 留档，判据变化时无需重新解析全量
    for e in list(state):
        if e not in entries:
            del state[e]            # 上游已删除的条目同步移除
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
    """去掉注释与文档字符串，只保留可执行代码。"""
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
        dst = os.path.join(d, name)
        if not os.path.exists(src) or os.path.abspath(src) == os.path.abspath(dst):
            continue
        with open(dst, "w") as f:
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

    slug = "FlandreScarle7/china_max_fixed"
    if GIT_REMOTE and ":" in GIT_REMOTE:
        slug = GIT_REMOTE.split(":")[-1].removesuffix(".git")
    base = f"{RAW_BASE}/{slug}/main"
    drop = len(entries) - len(keep)
    with open(os.path.join(REPO, "README.md"), "w") as f:
        f.write(f"""# china_max_fixed

经中国大陆境内递归 DNS 实测解析与 MaxMind GeoLite2 校验清洗的直连域名列表。每日自动化增量审计。

---

## 核心机制

针对常见大陆直连域名集（如包含境外节点、CDN Anycast 误报或仅依托管辖区判定）导致的直连流量走偏与 DNS 泄漏问题，本项目对上游全量域名进行端到端实测清洗：

- **数据上游**：合并 [blackmatrix7/ChinaMax](https://github.com/blackmatrix7/ios_rule_script) 与 [v2fly/geosite:cn](https://github.com/v2fly/domain-list-community) 全量条目并展开递归引用。
- **探测环境**：运行于中国大陆境内节点，通过双路独立递归解析器（腾讯云内网解析 + 阿里公共 DNS）实测解析 apex 与 `www` 记录。
- **判定标准**：解析出的真实 A 记录在 MaxMind GeoLite2 数据库中必须满足 `country.iso_code == "CN"`。独立代码区域（HK / MO / TW）及仅注册国为 CN 的境外机房一律排除。
- **状态滚动**：维护 `state.json` 历史探测状态。每日审计上游增量及 1/30 存量条目（30 天全量滚动一次）；采用 `FAIL_MAX = 7` 容错缓冲机制，避免地理 DNS 偶发波动导致误删。
- **去重规则**：判定完成后执行后缀树剪枝（如 `+.example.com` 覆盖 `*.a.example.com`）。

---

## 规则集状态

| 指标 | 数据 |
| :--- | :--- |
| 上游原始条目 | {len(entries):,} |
| 实测清洗保留 | {len(keep):,} |
| 剔除境外/无效 | {drop:,} ({drop/max(len(entries),1)*100:.1f}%) |
| GeoLite2 构建时间 | {built} |
| 最近更新 (UTC) | {ts} |

---

## 订阅与配置

### 1. Clash / Mihomo (YAML Rule-Provider)

```yaml
rule-providers:
  China_Domain:
    type: http
    behavior: domain
    format: yaml
    interval: 86400
    url: '{base}/yaml/ChinaMax_Domain.yaml'
    path: './ruleset/ChinaMax_Domain.yaml'
```

### 2. Surge / Quantumult X / Shadowrocket (纯文本列表)

- **URL**: `{base}/list/ChinaMax_Domain.list`
- **Surge 规则**:
  ```ini
  DOMAIN-SET,{base}/list/ChinaMax_Domain.list,DIRECT
  ```

---

## 项目结构

- `tools/audit.py`：审计与清洗核心引擎（无第三方重依赖，纯 Python 标准库 + mmdb 解析）。
- `cidr_overrides.txt`：用于纠正个别 ASN/BGP 宣告偏差的人工静态 CIDR 覆盖表。
- `state.json`：历史探测状态与滚动窗口持久化记录。

## 许可说明

- 规则集上游源自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)。
- GeoIP 基础数据由 MaxMind GeoLite2 提供（遵从 [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula)）。
- 本项目脚本按 MIT 协议开源。
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
           f"由 audit.py 每日自动生成。")
    git("commit", "-q", "-m", msg)
    r = git("push", "-u", "origin", "main", check=False)
    if r.returncode:
        raise SystemExit(f"推送失败: {r.stderr.strip()[:300]}")
    log("已推送到 GitHub")

if __name__ == "__main__":
    main()
