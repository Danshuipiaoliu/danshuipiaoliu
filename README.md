# NS 协议模拟平台（Python）

这是一个“教学级 + 实验级”的综合网络协议模拟平台，包含：

- 可靠传输协议：滑动窗口、超时重传、ACK 回传
- 网络攻击仿真：丢包攻击、重放攻击、时延尖峰攻击
- 拥塞控制：AIMD（加性增大、乘性减小）
- 实验统计：吞吐、有效吞吐、丢包率、重传次数、CWND 统计
- 实时可视化：可选绘制拥塞窗口与确认进度曲线

## 快速开始

```bash
python3 ns_platform.py --attack basic --message-size 300 --plot
```

## 常用参数

- `--attack {none,basic,aggressive}`：攻击配置
- `--message-size`：消息总长度（字符）
- `--loss-rate`：基础随机丢包率
- `--timeout-ms`：超时重传阈值
- `--seed`：随机种子（复现实验）
- `--export-csv`：导出 tick 级指标 CSV 路径
- `--plot`：启用 matplotlib 曲线图

## 输出结果

- 控制台打印实验摘要：完整性、丢包率、重传次数、完成时延、吞吐等
- `artifacts/metrics.csv`：每个 tick 的 `cwnd/inflight/acked/retransmissions`

## 扩展建议

1. 新增攻击模型：按 `Attack` 基类扩展 `mutate_packet/extra_delay`
2. 替换拥塞控制：实现 Reno/CUBIC/BBR 风格控制器
3. 支持多流竞争：引入多 Sender 与共享瓶颈链路
4. 支持更多可靠协议：GBN/SR/QUIC-like 机制
