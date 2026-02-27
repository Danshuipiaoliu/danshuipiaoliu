#!/usr/bin/env python3
"""教学级 + 实验级 NS 协议模拟平台（Python 实现）

特性:
1. 可靠传输协议: 滑动窗口 + 超时重传 + ACK
2. 网络攻击仿真: 丢包/重放/延迟尖峰（可组合）
3. 拥塞控制: AIMD
4. 动态演示:
   - CLI 实时 tick 输出
   - Tkinter + Matplotlib 交互可视化界面
5. 实验统计: CSV 导出 + 关键指标汇总
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import time
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
    message_size: int = 300
    mtu_payload: int = 10
    base_delay_ms: int = 60
    jitter_ms: int = 25
    loss_rate: float = 0.03
    corruption_rate: float = 0.0
    timeout_ms: int = 220
    max_ticks: int = 30000
    random_seed: int = 7
    message_pattern: str = "alphabet"


class Attack:
    name: str = "base"

    def mutate_packet(self, packet: Packet, now: int) -> Optional[Packet]:
        return packet

    def extra_delay(self, packet: Packet, now: int) -> int:
        return 0


class PacketDropAttack(Attack):
    name = "packet_drop_attack"

    def __init__(self, seq_mod: int = 7, drop_probability: float = 0.35):
        self.seq_mod = max(seq_mod, 1)
        self.drop_probability = max(0.0, min(drop_probability, 1.0))

    def mutate_packet(self, packet: Packet, now: int) -> Optional[Packet]:
        if packet.seq % self.seq_mod == 0 and random.random() < self.drop_probability:
            return None
        return packet


class ReplayAttack(Attack):
    name = "replay_attack"

    def __init__(self, trigger_mod: int = 11):
        self.trigger_mod = max(trigger_mod, 1)
        self.replayed: set[int] = set()

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
        self.spike_ms = max(spike_ms, 0)

    def extra_delay(self, packet: Packet, now: int) -> int:
        if self.start_tick <= now <= self.end_tick:
            return self.spike_ms
        return 0


class AIMDController:
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

        for attack in self.attacks:
            replay_copy = getattr(attack, "replay_copy", None)
            if callable(replay_copy):
                ghost = replay_copy(packet, now)
                if ghost is not None:
                    ghost_delay = delay + random.randint(20, 80)
                    self.inflight.append(DeliveryEvent(deliver_at=now + ghost_delay, packet=ghost))
        return True

    def recv_ready(self, now: int) -> List[Packet]:
        ready: List[Packet] = []
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

    def handle_ack(self, ack: Ack) -> None:
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


class SimulationEngine:
    """可步进/可暂停的仿真引擎，用于 CLI 和 GUI 动态演示。"""

    def __init__(self, config: ExperimentConfig, attacks: Optional[List[Attack]] = None):
        random.seed(config.random_seed)
        self.config = config
        self.message = self._build_message(config.message_size, config.message_pattern)
        self.cc = AIMDController()
        self.sender = Sender(data=self.message, config=config, cc=self.cc)
        self.receiver = Receiver()
        self.data_ch = NetworkChannel(config=config, attacks=attacks)
        self.ack_ch = NetworkChannel(config=config, attacks=[])
        self.stats = ExperimentStats()
        self.tick = 0
        self.done = False

    @staticmethod
    def _build_message(size: int, pattern: str) -> str:
        if pattern == "alphabet":
            return "".join(chr(ord("a") + i % 26) for i in range(size))
        if pattern == "digits":
            return "".join(str(i % 10) for i in range(size))
        if pattern == "binary":
            return "".join("01"[i % 2] for i in range(size))
        raise ValueError(f"Unknown message pattern: {pattern}")

    def step(self, steps: int = 1) -> None:
        for _ in range(steps):
            if self.done or self.tick >= self.config.max_ticks:
                self.finalize()
                break

            self.sender.send_new(self.data_ch, self.tick, self.stats)
            for packet in self.data_ch.recv_ready(self.tick):
                ack = self.receiver.on_packet(packet, self.tick)
                self.ack_ch.send(Packet(seq=ack.seq, payload="ACK", sent_at=self.tick), self.tick)

            for ack_packet in self.ack_ch.recv_ready(self.tick):
                self.sender.handle_ack(Ack(seq=ack_packet.seq, sent_at=self.tick))

            self.sender.handle_timeouts(self.data_ch, self.tick, self.stats)

            self.stats.metrics.append(
                TickMetric(
                    tick=self.tick,
                    cwnd=self.cc.cwnd,
                    inflight=max(self.sender.next_seq - self.sender.base, 0),
                    acked=len(self.sender.acked),
                    retransmissions=self.stats.retransmissions,
                )
            )

            if self.sender.done():
                self.done = True
                self.finalize()
                break
            self.tick += 1

    def finalize(self) -> None:
        if self.stats.completion_tick:
            return
        self.stats.completion_tick = self.tick
        seconds = max(self.tick / 1000.0, 1e-9)
        self.stats.throughput_chars_per_s = self.stats.tx_total * self.config.mtu_payload / seconds
        self.stats.goodput_chars_per_s = len(self.receiver.reassembled()) / seconds
        self.done = True

    def integrity_passed(self) -> bool:
        return len(self.receiver.reassembled()) == self.config.message_size


def run_experiment(config: ExperimentConfig, attacks: Optional[List[Attack]] = None) -> Tuple[str, ExperimentStats]:
    engine = SimulationEngine(config=config, attacks=attacks)
    while not engine.done and engine.tick < config.max_ticks:
        engine.step()
    engine.finalize()
    return engine.receiver.reassembled(), engine.stats


def export_metrics_csv(stats: ExperimentStats, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["tick", "cwnd", "inflight", "acked", "retransmissions"])
        for m in stats.metrics:
            writer.writerow([m.tick, f"{m.cwnd:.4f}", m.inflight, m.acked, m.retransmissions])


def build_attacks(
    profile: str,
    enable_drop: bool = True,
    drop_seq_mod: int = 9,
    drop_probability: float = 0.35,
    enable_replay: bool = False,
    replay_trigger_mod: int = 8,
    enable_delay_spike: bool = True,
    delay_start_tick: int = 300,
    delay_end_tick: int = 800,
    delay_spike_ms: int = 180,
) -> List[Attack]:
    if profile == "none":
        return []

    if profile == "basic":
        attacks: List[Attack] = []
        if enable_drop:
            attacks.append(PacketDropAttack(seq_mod=drop_seq_mod, drop_probability=drop_probability))
        if enable_delay_spike:
            attacks.append(DelaySpikeAttack(start_tick=delay_start_tick, end_tick=delay_end_tick, spike_ms=delay_spike_ms))
        return attacks

    if profile == "aggressive":
        attacks = [PacketDropAttack(seq_mod=5, drop_probability=0.55), ReplayAttack(trigger_mod=8), DelaySpikeAttack(start_tick=200, end_tick=1500, spike_ms=260)]
        return attacks

    if profile == "custom":
        attacks = []
        if enable_drop:
            attacks.append(PacketDropAttack(seq_mod=drop_seq_mod, drop_probability=drop_probability))
        if enable_replay:
            attacks.append(ReplayAttack(trigger_mod=replay_trigger_mod))
        if enable_delay_spike:
            attacks.append(DelaySpikeAttack(start_tick=delay_start_tick, end_tick=delay_end_tick, spike_ms=delay_spike_ms))
        return attacks

    raise ValueError(f"Unknown attack profile: {profile}")


def load_json_config(path: Optional[Path]) -> Dict[str, object]:
    if not path:
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def print_realtime_tick(engine: SimulationEngine, every: int = 50) -> None:
    if not engine.stats.metrics:
        return
    metric = engine.stats.metrics[-1]
    if metric.tick % max(every, 1) == 0:
        print(
            f"tick={metric.tick:5d} cwnd={metric.cwnd:6.2f} inflight={metric.inflight:3d} "
            f"acked={metric.acked:3d} retrans={metric.retransmissions:3d}"
        )


def maybe_plot(stats: ExperimentStats) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        print("[warn] matplotlib 不可用，跳过图形绘制。")
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


def launch_gui(default_config: ExperimentConfig) -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception as exc:
        raise RuntimeError("Tkinter 不可用，无法启动 GUI。") from exc

    class NSPlatformGUI:
        def __init__(self, root: "tk.Tk"):
            self.root = root
            self.root.title("NS 协议教学实验平台 - 动态演示")
            self.root.geometry("1200x760")
            self.engine: Optional[SimulationEngine] = None
            self.running = False

            self.vars = {
                "message_size": tk.IntVar(value=default_config.message_size),
                "mtu_payload": tk.IntVar(value=default_config.mtu_payload),
                "base_delay_ms": tk.IntVar(value=default_config.base_delay_ms),
                "jitter_ms": tk.IntVar(value=default_config.jitter_ms),
                "loss_rate": tk.DoubleVar(value=default_config.loss_rate),
                "timeout_ms": tk.IntVar(value=default_config.timeout_ms),
                "seed": tk.IntVar(value=default_config.random_seed),
                "max_ticks": tk.IntVar(value=default_config.max_ticks),
                "drop_enabled": tk.BooleanVar(value=True),
                "drop_seq_mod": tk.IntVar(value=9),
                "drop_probability": tk.DoubleVar(value=0.35),
                "replay_enabled": tk.BooleanVar(value=True),
                "replay_trigger_mod": tk.IntVar(value=8),
                "delay_enabled": tk.BooleanVar(value=True),
                "delay_start": tk.IntVar(value=300),
                "delay_end": tk.IntVar(value=800),
                "delay_spike": tk.IntVar(value=180),
            }

            self._build_layout(ttk)
            self._build_plot_area(ttk)
            self._log("GUI 已就绪：请点击 初始化仿真。")

        def _build_layout(self, ttk_module) -> None:
            left = ttk_module.Frame(self.root, padding=8)
            left.pack(side="left", fill="y")
            right = ttk_module.Frame(self.root, padding=8)
            right.pack(side="right", fill="both", expand=True)
            self.right_panel = right

            row = 0
            for key, label in [
                ("message_size", "消息长度"),
                ("mtu_payload", "分片大小(MTU payload)"),
                ("base_delay_ms", "基础时延(ms)"),
                ("jitter_ms", "时延抖动(ms)"),
                ("loss_rate", "基础丢包率"),
                ("timeout_ms", "超时重传阈值(ms)"),
                ("seed", "随机种子"),
                ("max_ticks", "最大仿真tick"),
            ]:
                ttk_module.Label(left, text=label).grid(row=row, column=0, sticky="w", pady=2)
                ttk_module.Entry(left, textvariable=self.vars[key], width=16).grid(row=row, column=1, pady=2)
                row += 1

            ttk_module.Separator(left, orient="horizontal").grid(row=row, column=0, columnspan=2, sticky="ew", pady=8)
            row += 1
            ttk_module.Label(left, text="攻击配置（可自由组合）").grid(row=row, column=0, columnspan=2, sticky="w")
            row += 1

            ttk_module.Checkbutton(left, text="启用丢包攻击", variable=self.vars["drop_enabled"]).grid(row=row, column=0, sticky="w")
            row += 1
            ttk_module.Label(left, text="  seq_mod / probability").grid(row=row, column=0, sticky="w")
            ttk_module.Entry(left, textvariable=self.vars["drop_seq_mod"], width=7).grid(row=row, column=1, sticky="w")
            row += 1
            ttk_module.Entry(left, textvariable=self.vars["drop_probability"], width=7).grid(row=row, column=1, sticky="w")
            row += 1

            ttk_module.Checkbutton(left, text="启用重放攻击", variable=self.vars["replay_enabled"]).grid(row=row, column=0, sticky="w")
            ttk_module.Entry(left, textvariable=self.vars["replay_trigger_mod"], width=7).grid(row=row, column=1, sticky="w")
            row += 1

            ttk_module.Checkbutton(left, text="启用时延尖峰", variable=self.vars["delay_enabled"]).grid(row=row, column=0, sticky="w")
            row += 1
            ttk_module.Label(left, text="  start / end / spike(ms)").grid(row=row, column=0, sticky="w")
            ttk_module.Entry(left, textvariable=self.vars["delay_start"], width=7).grid(row=row, column=1, sticky="w")
            row += 1
            ttk_module.Entry(left, textvariable=self.vars["delay_end"], width=7).grid(row=row, column=1, sticky="w")
            row += 1
            ttk_module.Entry(left, textvariable=self.vars["delay_spike"], width=7).grid(row=row, column=1, sticky="w")
            row += 1

            ttk_module.Button(left, text="初始化仿真", command=self.init_engine).grid(row=row, column=0, columnspan=2, sticky="ew", pady=4)
            row += 1
            ttk_module.Button(left, text="单步 +1", command=lambda: self.step_engine(1)).grid(row=row, column=0, sticky="ew")
            ttk_module.Button(left, text="快进 +20", command=lambda: self.step_engine(20)).grid(row=row, column=1, sticky="ew")
            row += 1
            ttk_module.Button(left, text="运行/暂停", command=self.toggle_run).grid(row=row, column=0, sticky="ew", pady=2)
            ttk_module.Button(left, text="导出CSV", command=self.export_csv_dialog).grid(row=row, column=1, sticky="ew", pady=2)
            row += 1
            ttk_module.Button(left, text="保存参数JSON", command=self.save_json_dialog).grid(row=row, column=0, sticky="ew")
            ttk_module.Button(left, text="加载参数JSON", command=self.load_json_dialog).grid(row=row, column=1, sticky="ew")
            row += 1

            self.progress = ttk_module.Progressbar(left, orient="horizontal", mode="determinate", length=240)
            self.progress.grid(row=row, column=0, columnspan=2, sticky="ew", pady=8)
            row += 1

            self.status_label = ttk_module.Label(left, text="状态: idle")
            self.status_label.grid(row=row, column=0, columnspan=2, sticky="w")
            row += 1

            self.log_text = tk.Text(left, width=34, height=16)
            self.log_text.grid(row=row, column=0, columnspan=2, pady=4)

        def _build_plot_area(self, ttk_module) -> None:
            self.plot_info = ttk_module.Label(self.right_panel, text="等待初始化后显示动态曲线", anchor="w")
            self.plot_info.pack(fill="x")
            self.plot_canvas = None
            self.fig = None
            self.ax1 = None
            self.ax2 = None
            self.line_cwnd = None
            self.line_acked = None

            try:
                from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
                from matplotlib.figure import Figure
            except Exception:
                self.plot_info.config(text="matplotlib 不可用，仅显示文本/进度动态演示。")
                return

            self.fig = Figure(figsize=(8.4, 5.6), dpi=100)
            self.ax1 = self.fig.add_subplot(111)
            self.ax2 = self.ax1.twinx()
            self.line_cwnd, = self.ax1.plot([], [], color="tab:blue", label="CWND")
            self.line_acked, = self.ax2.plot([], [], color="tab:orange", label="Acked")
            self.ax1.set_xlabel("Tick")
            self.ax1.set_ylabel("CWND")
            self.ax2.set_ylabel("Acked")
            self.plot_canvas = FigureCanvasTkAgg(self.fig, master=self.right_panel)
            self.plot_canvas.get_tk_widget().pack(fill="both", expand=True)

        def _log(self, message: str) -> None:
            self.log_text.insert("end", f"{message}\n")
            self.log_text.see("end")

        def _config(self) -> ExperimentConfig:
            return ExperimentConfig(
                message_size=self.vars["message_size"].get(),
                mtu_payload=self.vars["mtu_payload"].get(),
                base_delay_ms=self.vars["base_delay_ms"].get(),
                jitter_ms=self.vars["jitter_ms"].get(),
                loss_rate=self.vars["loss_rate"].get(),
                timeout_ms=self.vars["timeout_ms"].get(),
                random_seed=self.vars["seed"].get(),
                max_ticks=self.vars["max_ticks"].get(),
            )

        def _attacks(self) -> List[Attack]:
            return build_attacks(
                profile="custom",
                enable_drop=self.vars["drop_enabled"].get(),
                drop_seq_mod=self.vars["drop_seq_mod"].get(),
                drop_probability=self.vars["drop_probability"].get(),
                enable_replay=self.vars["replay_enabled"].get(),
                replay_trigger_mod=self.vars["replay_trigger_mod"].get(),
                enable_delay_spike=self.vars["delay_enabled"].get(),
                delay_start_tick=self.vars["delay_start"].get(),
                delay_end_tick=self.vars["delay_end"].get(),
                delay_spike_ms=self.vars["delay_spike"].get(),
            )

        def init_engine(self) -> None:
            self.engine = SimulationEngine(self._config(), self._attacks())
            self.running = False
            self.status_label.config(text="状态: initialized")
            self.progress.config(maximum=self.engine.config.max_ticks, value=0)
            self._log("仿真已初始化，可单步/快进/连续运行。")
            self.refresh_ui()

        def step_engine(self, steps: int) -> None:
            if not self.engine:
                self.init_engine()
            assert self.engine is not None
            self.engine.step(steps)
            self.refresh_ui()
            if self.engine.done:
                self.running = False
                self._log("仿真结束: " + json.dumps(self.engine.stats.summary(), ensure_ascii=False))

        def toggle_run(self) -> None:
            if not self.engine:
                self.init_engine()
            self.running = not self.running
            self.status_label.config(text=f"状态: {'running' if self.running else 'paused'}")
            if self.running:
                self._schedule()

        def _schedule(self) -> None:
            if not self.running:
                return
            self.step_engine(5)
            if self.engine and not self.engine.done:
                self.root.after(50, self._schedule)

        def refresh_ui(self) -> None:
            if not self.engine:
                return
            self.progress.config(value=self.engine.tick)
            summary = self.engine.stats.summary()
            self.status_label.config(
                text=(
                    f"状态: {'done' if self.engine.done else 'running'} | tick={self.engine.tick} "
                    f"acked={len(self.engine.sender.acked)} cwnd={self.engine.cc.cwnd:.2f}"
                )
            )
            self.plot_info.config(
                text=f"loss={summary['packet_loss_ratio']:.3f} retrans={summary['retransmissions']} "
                f"goodput={summary['goodput_chars_per_s']:.2f}"
            )
            self._refresh_plot()

        def _refresh_plot(self) -> None:
            if not self.engine or not self.plot_canvas or not self.line_cwnd or not self.line_acked:
                return
            ticks = [m.tick for m in self.engine.stats.metrics]
            cwnd = [m.cwnd for m in self.engine.stats.metrics]
            acked = [m.acked for m in self.engine.stats.metrics]
            self.line_cwnd.set_data(ticks, cwnd)
            self.line_acked.set_data(ticks, acked)
            if ticks:
                self.ax1.set_xlim(0, max(ticks[-1], 100))
            self.ax1.set_ylim(0, max(cwnd + [5]) + 1)
            self.ax2.set_ylim(0, max(acked + [5]) + 1)
            self.plot_canvas.draw_idle()

        def export_csv_dialog(self) -> None:
            if not self.engine:
                self._log("请先初始化/运行仿真后再导出。")
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not path:
                return
            export_metrics_csv(self.engine.stats, Path(path))
            self._log(f"已导出: {path}")

        def save_json_dialog(self) -> None:
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if not path:
                return
            data = {k: v.get() for k, v in self.vars.items()}
            with Path(path).open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self._log(f"参数已保存: {path}")

        def load_json_dialog(self) -> None:
            path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
            if not path:
                return
            with Path(path).open("r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.items():
                if k in self.vars:
                    self.vars[k].set(v)
            self._log(f"参数已加载: {path}")

    root = tk.Tk()
    NSPlatformGUI(root)
    root.mainloop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NS 协议综合实验平台")
    parser.add_argument("--attack", choices=["none", "basic", "aggressive", "custom"], default="basic")
    parser.add_argument("--message-size", type=int, default=300)
    parser.add_argument("--mtu-payload", type=int, default=10)
    parser.add_argument("--base-delay-ms", type=int, default=60)
    parser.add_argument("--jitter-ms", type=int, default=25)
    parser.add_argument("--loss-rate", type=float, default=0.03)
    parser.add_argument("--timeout-ms", type=int, default=220)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-ticks", type=int, default=30000)
    parser.add_argument("--message-pattern", choices=["alphabet", "digits", "binary"], default="alphabet")
    parser.add_argument("--export-csv", type=Path, default=Path("artifacts/metrics.csv"))
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--live", action="store_true", help="CLI 动态输出 tick 指标")
    parser.add_argument("--live-interval", type=int, default=100)
    parser.add_argument("--gui", action="store_true", help="启动可视化交互界面")
    parser.add_argument("--config-json", type=Path, help="读取 JSON 覆盖参数")

    parser.add_argument("--drop-enabled", action="store_true")
    parser.add_argument("--drop-seq-mod", type=int, default=9)
    parser.add_argument("--drop-probability", type=float, default=0.35)
    parser.add_argument("--replay-enabled", action="store_true")
    parser.add_argument("--replay-trigger-mod", type=int, default=8)
    parser.add_argument("--delay-enabled", action="store_true")
    parser.add_argument("--delay-start", type=int, default=300)
    parser.add_argument("--delay-end", type=int, default=800)
    parser.add_argument("--delay-spike", type=int, default=180)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    overrides = load_json_config(args.config_json)

    cfg = ExperimentConfig(
        message_size=int(overrides.get("message_size", args.message_size)),
        mtu_payload=int(overrides.get("mtu_payload", args.mtu_payload)),
        base_delay_ms=int(overrides.get("base_delay_ms", args.base_delay_ms)),
        jitter_ms=int(overrides.get("jitter_ms", args.jitter_ms)),
        loss_rate=float(overrides.get("loss_rate", args.loss_rate)),
        timeout_ms=int(overrides.get("timeout_ms", args.timeout_ms)),
        random_seed=int(overrides.get("seed", args.seed)),
        max_ticks=int(overrides.get("max_ticks", args.max_ticks)),
        message_pattern=str(overrides.get("message_pattern", args.message_pattern)),
    )

    if args.gui:
        launch_gui(cfg)
        return

    custom_drop = bool(overrides.get("drop_enabled", args.drop_enabled))
    custom_replay = bool(overrides.get("replay_enabled", args.replay_enabled))
    custom_delay = bool(overrides.get("delay_enabled", args.delay_enabled))

    attacks = build_attacks(
        profile=str(overrides.get("attack", args.attack)),
        enable_drop=custom_drop,
        drop_seq_mod=int(overrides.get("drop_seq_mod", args.drop_seq_mod)),
        drop_probability=float(overrides.get("drop_probability", args.drop_probability)),
        enable_replay=custom_replay,
        replay_trigger_mod=int(overrides.get("replay_trigger_mod", args.replay_trigger_mod)),
        enable_delay_spike=custom_delay,
        delay_start_tick=int(overrides.get("delay_start", args.delay_start)),
        delay_end_tick=int(overrides.get("delay_end", args.delay_end)),
        delay_spike_ms=int(overrides.get("delay_spike", args.delay_spike)),
    )

    engine = SimulationEngine(cfg, attacks)
    start = time.time()
    while not engine.done and engine.tick < cfg.max_ticks:
        engine.step()
        if args.live:
            print_realtime_tick(engine, every=args.live_interval)
    engine.finalize()
    elapsed = time.time() - start

    export_metrics_csv(engine.stats, args.export_csv)

    print("=== NS 协议模拟平台实验结果 ===")
    print(f"攻击配置: {overrides.get('attack', args.attack)}")
    print(f"数据完整性: {'PASS' if engine.integrity_passed() else 'FAIL'}")
    for k, v in engine.stats.summary().items():
        print(f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}")
    print(f"指标文件: {args.export_csv}")
    print(f"仿真耗时(秒): {elapsed:.4f}")

    if args.plot:
        maybe_plot(engine.stats)


if __name__ == "__main__":
    main()
