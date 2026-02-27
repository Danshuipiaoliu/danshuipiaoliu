#!/usr/bin/env python3
"""教学级 + 实验级 NS 协议模拟平台（Python 实现）

功能:
1. 可靠传输协议 (滑动窗口 + 超时重传)
2. 网络攻击仿真 (丢包/重放/延迟尖峰)
3. 拥塞控制 (AIMD)
4. 实时可视化 (可选 matplotlib)
5. 实验统计与结果导出
"""
from __future__ import annotations

import argparse
import csv
import random
import statistics
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class Packet:
    seq: int
    payload: str
    sent_at: int
    retransmit: bool = False


@dataclass
class Ack:
    seq: int
    sent_at: int


@dataclass
class ExperimentConfig:
    message_size: int = 200
    mtu_payload: int = 10
    base_delay_ms: int = 60
    jitter_ms: int = 25
    loss_rate: float = 0.03
    corruption_rate: float = 0.0
    timeout_ms: int = 220
    max_ticks: int = 30000
    random_seed: int = 7


class Attack:
    name: str = "base"

    def mutate_packet(self, packet: Packet, now: int) -> Optional[Packet]:
        return packet

    def extra_delay(self, packet: Packet, now: int) -> int:
        return 0


class PacketDropAttack(Attack):
    name = "packet_drop_attack"

    def __init__(self, seq_mod: int = 7, drop_probability: float = 0.35):
        self.seq_mod = seq_mod
        self.drop_probability = drop_probability

    def mutate_packet(self, packet: Packet, now: int) -> Optional[Packet]:
        if packet.seq % self.seq_mod == 0 and random.random() < self.drop_probability:
            return None
        return packet


class ReplayAttack(Attack):
    name = "replay_attack"

    def __init__(self, trigger_mod: int = 11):
        self.trigger_mod = trigger_mod
        self.replayed: set[int] = set()

    def mutate_packet(self, packet: Packet, now: int) -> Optional[Packet]:
        return packet

    def replay_copy(self, packet: Packet, now: int) -> Optional[Packet]:
        if packet.seq % self.trigger_mod == 0 and packet.seq not in self.replayed:
            self.replayed.add(packet.seq)
            return Packet(seq=packet.seq, payload=packet.payload, sent_at=now, retransmit=True)
        return None


class DelaySpikeAttack(Attack):
    name = "delay_spike_attack"

    def __init__(self, start_tick: int = 300, end_tick: int = 1000, spike_ms: int = 300):
        self.start_tick = start_tick
        self.end_tick = end_tick
        self.spike_ms = spike_ms

    def extra_delay(self, packet: Packet, now: int) -> int:
        if self.start_tick <= now <= self.end_tick:
            return self.spike_ms
        return 0


class AIMDController:
    """Additive Increase Multiplicative Decrease"""

    def __init__(self, init_cwnd: float = 4.0, min_cwnd: float = 1.0):
        self.cwnd = init_cwnd
        self.ssthresh = 16.0
        self.min_cwnd = min_cwnd

    @property
    def window(self) -> int:
        return max(int(self.cwnd), 1)

    def on_ack(self) -> None:
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            self.cwnd += 1.0 / self.cwnd

    def on_loss(self) -> None:
        self.ssthresh = max(self.cwnd / 2.0, self.min_cwnd)
        self.cwnd = max(self.ssthresh, self.min_cwnd)


@dataclass
class DeliveryEvent:
    deliver_at: int
    packet: Packet


class NetworkChannel:
    def __init__(self, config: ExperimentConfig, attacks: Optional[List[Attack]] = None):
        self.config = config
        self.attacks = attacks or []
        self.inflight: Deque[DeliveryEvent] = deque()

    def send(self, packet: Packet, now: int) -> bool:
        if random.random() < self.config.loss_rate:
            return False
        if random.random() < self.config.corruption_rate:
            return False

        p: Optional[Packet] = packet
        for attack in self.attacks:
            if p is None:
                break
            p = attack.mutate_packet(p, now)
        if p is None:
            return False

        delay = self.config.base_delay_ms + random.randint(0, self.config.jitter_ms)
        for attack in self.attacks:
            delay += attack.extra_delay(p, now)

        self.inflight.append(DeliveryEvent(deliver_at=now + delay, packet=p))

        # replay injection
        for attack in self.attacks:
            replay_copy = getattr(attack, "replay_copy", None)
            if callable(replay_copy):
                ghost = replay_copy(packet, now)
                if ghost is not None:
                    ghost_delay = delay + random.randint(20, 80)
                    self.inflight.append(DeliveryEvent(deliver_at=now + ghost_delay, packet=ghost))
        return True

    def recv_ready(self, now: int) -> List[Packet]:
        ready = []
        while self.inflight and self.inflight[0].deliver_at <= now:
            ready.append(self.inflight.popleft().packet)
        return ready


class Sender:
    def __init__(self, data: str, config: ExperimentConfig, cc: AIMDController):
        self.config = config
        self.cc = cc
        self.chunks = [data[i : i + config.mtu_payload] for i in range(0, len(data), config.mtu_payload)]
        self.base = 0
        self.next_seq = 0
        self.sent: Dict[int, Packet] = {}
        self.acked: set[int] = set()

    def done(self) -> bool:
        return len(self.acked) >= len(self.chunks)

    def send_new(self, channel: NetworkChannel, now: int, stats: "ExperimentStats") -> None:
        window_limit = self.base + self.cc.window
        while self.next_seq < len(self.chunks) and self.next_seq < window_limit:
            pkt = Packet(seq=self.next_seq, payload=self.chunks[self.next_seq], sent_at=now)
            delivered = channel.send(pkt, now)
            self.sent[pkt.seq] = pkt
            stats.tx_total += 1
            if not delivered:
                stats.tx_dropped_before_delivery += 1
            self.next_seq += 1

    def handle_ack(self, ack: Ack, stats: "ExperimentStats") -> None:
        if ack.seq not in self.acked:
            self.acked.add(ack.seq)
            self.cc.on_ack()
            if ack.seq == self.base:
                while self.base in self.acked:
                    self.base += 1

    def handle_timeouts(self, channel: NetworkChannel, now: int, stats: "ExperimentStats") -> None:
        for seq in range(self.base, self.next_seq):
            if seq in self.acked:
                continue
            pkt = self.sent.get(seq)
            if pkt and now - pkt.sent_at > self.config.timeout_ms:
                self.cc.on_loss()
                resend = Packet(seq=seq, payload=pkt.payload, sent_at=now, retransmit=True)
                self.sent[seq] = resend
                delivered = channel.send(resend, now)
                stats.retransmissions += 1
                stats.tx_total += 1
                if not delivered:
                    stats.tx_dropped_before_delivery += 1


class Receiver:
    def __init__(self):
        self.buffer: Dict[int, str] = {}

    def on_packet(self, packet: Packet, now: int) -> Ack:
        self.buffer[packet.seq] = packet.payload
        return Ack(seq=packet.seq, sent_at=now)

    def reassembled(self) -> str:
        return "".join(v for _, v in sorted(self.buffer.items(), key=lambda kv: kv[0]))


@dataclass
class TickMetric:
    tick: int
    cwnd: float
    inflight: int
    acked: int
    retransmissions: int


@dataclass
class ExperimentStats:
    tx_total: int = 0
    tx_dropped_before_delivery: int = 0
    retransmissions: int = 0
    completion_tick: int = 0
    throughput_chars_per_s: float = 0.0
    goodput_chars_per_s: float = 0.0
    metrics: List[TickMetric] = field(default_factory=list)

    def summary(self) -> Dict[str, float]:
        packet_loss_ratio = self.tx_dropped_before_delivery / self.tx_total if self.tx_total else 0.0
        cwnd_avg = statistics.mean([m.cwnd for m in self.metrics]) if self.metrics else 0.0
        cwnd_max = max([m.cwnd for m in self.metrics], default=0.0)
        return {
            "tx_total": self.tx_total,
            "tx_dropped_before_delivery": self.tx_dropped_before_delivery,
            "packet_loss_ratio": packet_loss_ratio,
            "retransmissions": self.retransmissions,
            "completion_tick": self.completion_tick,
            "throughput_chars_per_s": self.throughput_chars_per_s,
            "goodput_chars_per_s": self.goodput_chars_per_s,
            "avg_cwnd": cwnd_avg,
            "max_cwnd": cwnd_max,
        }


def run_experiment(config: ExperimentConfig, attacks: Optional[List[Attack]] = None) -> Tuple[str, ExperimentStats]:
    random.seed(config.random_seed)
    message = "".join(chr(ord("a") + i % 26) for i in range(config.message_size))

    cc = AIMDController()
    sender = Sender(data=message, config=config, cc=cc)
    receiver = Receiver()
    data_ch = NetworkChannel(config=config, attacks=attacks)
    ack_ch = NetworkChannel(config=config, attacks=[])
    stats = ExperimentStats()

    for tick in range(config.max_ticks):
        sender.send_new(data_ch, tick, stats)

        for packet in data_ch.recv_ready(tick):
            ack = receiver.on_packet(packet, tick)
            ack_ch.send(Packet(seq=ack.seq, payload="ACK", sent_at=tick), tick)

        for ack_packet in ack_ch.recv_ready(tick):
            sender.handle_ack(Ack(seq=ack_packet.seq, sent_at=tick), stats)

        sender.handle_timeouts(data_ch, tick, stats)

        stats.metrics.append(
            TickMetric(
                tick=tick,
                cwnd=cc.cwnd,
                inflight=max(sender.next_seq - sender.base, 0),
                acked=len(sender.acked),
                retransmissions=stats.retransmissions,
            )
        )

        if sender.done():
            stats.completion_tick = tick
            seconds = max(tick / 1000.0, 1e-9)
            stats.throughput_chars_per_s = stats.tx_total * config.mtu_payload / seconds
            stats.goodput_chars_per_s = len(receiver.reassembled()) / seconds
            break
    else:
        stats.completion_tick = config.max_ticks

    return receiver.reassembled(), stats


def export_metrics_csv(stats: ExperimentStats, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["tick", "cwnd", "inflight", "acked", "retransmissions"])
        for m in stats.metrics:
            writer.writerow([m.tick, f"{m.cwnd:.4f}", m.inflight, m.acked, m.retransmissions])


def maybe_plot(stats: ExperimentStats) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        print("[warn] matplotlib 不可用，跳过实时可视化。")
        return

    ticks = [m.tick for m in stats.metrics]
    cwnd = [m.cwnd for m in stats.metrics]
    acked = [m.acked for m in stats.metrics]

    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax1.plot(ticks, cwnd, label="CWND", color="tab:blue")
    ax1.set_xlabel("Tick (ms)")
    ax1.set_ylabel("Congestion Window", color="tab:blue")

    ax2 = ax1.twinx()
    ax2.plot(ticks, acked, label="Acked", color="tab:orange")
    ax2.set_ylabel("Acked Packets", color="tab:orange")

    plt.title("NS 教学/实验平台：拥塞窗口与确认进度")
    fig.tight_layout()
    plt.show()


def build_attacks(name: str) -> List[Attack]:
    if name == "none":
        return []
    if name == "basic":
        return [PacketDropAttack(seq_mod=9, drop_probability=0.35), DelaySpikeAttack(start_tick=300, end_tick=800, spike_ms=180)]
    if name == "aggressive":
        return [
            PacketDropAttack(seq_mod=5, drop_probability=0.55),
            ReplayAttack(trigger_mod=8),
            DelaySpikeAttack(start_tick=200, end_tick=1500, spike_ms=260),
        ]
    raise ValueError(f"Unknown attack profile: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="NS 协议综合实验平台")
    parser.add_argument("--attack", choices=["none", "basic", "aggressive"], default="basic")
    parser.add_argument("--message-size", type=int, default=300)
    parser.add_argument("--loss-rate", type=float, default=0.03)
    parser.add_argument("--timeout-ms", type=int, default=220)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--export-csv", type=Path, default=Path("artifacts/metrics.csv"))
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()

    cfg = ExperimentConfig(
        message_size=args.message_size,
        loss_rate=args.loss_rate,
        timeout_ms=args.timeout_ms,
        random_seed=args.seed,
    )
    attacks = build_attacks(args.attack)

    assembled, stats = run_experiment(cfg, attacks)
    export_metrics_csv(stats, args.export_csv)

    print("=== NS 协议模拟平台实验结果 ===")
    print(f"攻击配置: {args.attack}")
    print(f"数据完整性: {'PASS' if len(assembled) == args.message_size else 'FAIL'}")
    for k, v in stats.summary().items():
        if isinstance(v, float):
            print(f"{k}: {v:.4f}")
        else:
            print(f"{k}: {v}")
    print(f"指标文件: {args.export_csv}")

    if args.plot:
        maybe_plot(stats)


if __name__ == "__main__":
    main()
