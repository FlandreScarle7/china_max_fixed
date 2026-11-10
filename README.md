# china_max_fixed

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
| 上游原始条目 | 113,481 |
| 实测清洗保留 | 81,030 |
| 剔除境外/无效 | 32,451 (28.6%) |
| GeoLite2 构建时间 | 2026-11-06 |
| 最近更新 (UTC) | 2026-11-10 20:37:58 UTC |

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
    url: 'https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/yaml/ChinaMax_Domain.yaml'
    path: './ruleset/ChinaMax_Domain.yaml'
```

### 2. Surge / Quantumult X / Shadowrocket (纯文本列表)

- **URL**: `https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/list/ChinaMax_Domain.list`
- **Surge 规则**:
  ```ini
  DOMAIN-SET,https://raw.githubusercontent.com/FlandreScarle7/china_max_fixed/main/list/ChinaMax_Domain.list,DIRECT
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
