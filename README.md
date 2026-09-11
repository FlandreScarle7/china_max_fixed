# china_max_fixed

合并两个上游域名集合、经国内 DNS 实测校验后的中国大陆直连列表，每日更新。

## 为什么需要这个

常见的中国大陆直连域名列表几乎都源自 `dnsmasq-china-list`，
它的收录标准是「域名有大陆 NS 服务器」。

问题在于，用阿里云、腾讯云国际站建站的**境外网站**同样会被分到大陆 NS，
于是大量并非中国大陆的域名混进了这份列表
（参见 [blackmatrix7/ios_rule_script#1615](https://github.com/blackmatrix7/ios_rule_script/issues/1615)）。

把它们放进直连列表有两个后果：访问这些站点时**不走代理**，
以及**DNS 查询暴露**。对按域名分流的配置来说，这是静默失效。

本项目合并两个上游共 114,189 条逐条实测，其中 34,068 条（29.8%）
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
连续 7 次判定失败才真正剔除，避免地理 DNS 的随机性造成误删。
全量条目在 30 天内至少复核一次。

判定错误无法完全避免 —— 只要 GeoIP 把某个 IP 标成 CN，
该域名就会留在直连表里。`cidr_overrides.txt` 用于人工纠正已确认的个案。

## 当前状态

| | |
| --- | --- |
| 上游条目 | 114,189 |
| 保留 | 80,121 |
| 剔除 | 34,068（29.8%） |
| GeoLite2 构建于 | 2026-09-08 |
| 更新于 | 2026-09-11 20:32:12 UTC |

## 用法

两种格式内容相同，按需取用。

**YAML**（`behavior: domain` 规则集）

```
https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/yaml/ChinaMax_Domain.yaml
```

```yaml
rule-providers:
  China_Domain:
    type: http
    behavior: domain
    format: yaml
    interval: 86400
    url: 'https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/yaml/ChinaMax_Domain.yaml'
    path: './RuleSet/ChinaMax_Domain.yaml'
```

**纯文本列表**（每行一个域名，前导 `.` 表示含子域名）

```
https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/list/ChinaMax_Domain.list
```

```
DOMAIN-SET,https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/list/ChinaMax_Domain.list,DIRECT
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
