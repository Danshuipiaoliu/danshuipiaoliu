# NS 协议模拟平台（Python）

这是一个“教学级 + 实验级”的综合网络协议模拟平台，支持：

- 可靠传输协议：滑动窗口、ACK、超时重传
- 攻击仿真：丢包攻击、重放攻击、时延尖峰攻击（支持组合）
- 拥塞控制：AIMD（慢启动 + 拥塞避免 + 乘性减小）
- 动态演示：CLI 实时指标流 + GUI 动态曲线
- 实验统计：CSV 导出、吞吐/有效吞吐/丢包率/重传等

## 1. 快速开始

### 命令行实验

```bash
python3 ns_platform.py --attack basic --message-size 300 --export-csv artifacts/metrics.csv
```

### 命令行动态演示（实时输出）

```bash
python3 ns_platform.py --attack custom --drop-enabled --replay-enabled --delay-enabled --live --live-interval 50
```

### 可视化 GUI 演示

```bash
python3 ns_platform.py --gui
```

在 GUI 中可以：
- 单步执行、快进、连续运行/暂停
- 实时观察 CWND 与 ACK 进度变化
- 自由组合攻击参数（丢包/重放/时延）
- 导出 CSV、保存/加载 JSON 参数配置

## 2. 高自定义参数

### 基础网络参数
- `--message-size` 消息长度
- `--mtu-payload` 分片大小
- `--base-delay-ms` 基础时延
- `--jitter-ms` 抖动
- `--loss-rate` 随机丢包率
- `--timeout-ms` 重传超时
- `--max-ticks` 最大仿真时长
- `--message-pattern {alphabet,digits,binary}` 消息模式

### 攻击与故障参数
- `--attack {none,basic,aggressive,custom}`
- `--drop-enabled`
- `--drop-seq-mod`
- `--drop-probability`
- `--replay-enabled`
- `--replay-trigger-mod`
- `--delay-enabled`
- `--delay-start`
- `--delay-end`
- `--delay-spike`

### 配置复用
- `--config-json your_profile.json` 加载 JSON 配置覆盖 CLI 参数

## 3. 输出

- 控制台实验摘要（完整性、吞吐、有效吞吐、丢包率、CWND 统计）
- `artifacts/metrics.csv`（可自定义路径）
  - 字段：`tick, cwnd, inflight, acked, retransmissions`

## 4. 扩展建议

- 新增攻击模型：继承 `Attack` 并扩展 `mutate_packet/extra_delay`
- 新增拥塞算法：替换 `AIMDController`
- 支持多流竞争：多个 Sender 共享瓶颈链路
- 引入拓扑与路由：多跳链路 + 队列模型
