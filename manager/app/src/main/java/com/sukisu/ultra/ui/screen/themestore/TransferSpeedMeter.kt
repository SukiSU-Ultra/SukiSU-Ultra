package com.sukisu.ultra.ui.screen.themestore


internal data class TransferSpeedReading(
    val bytesPerSecond: Long,
    val etaSeconds: Long?,
)

/**
 * Sliding-window speed meter. Callbacks from resumable uploads and peer chunk
 * writes arrive at irregular intervals, so measuring the whole transfer would
 * hide stalls and short bursts. A five-second window keeps per-chunk burstiness
 * from making the MD3E progress block jump between extremes while still showing
 * a real stall within a few seconds.
 */
internal class TransferSpeedMeter(
    val totalBytes: Long,
    private val windowNanos: Long = 5_000_000_000L,
) {
    private val samples = ArrayDeque<Pair<Long, Long>>()

    @Synchronized
    fun update(transferredBytes: Long, nowNanos: Long = System.nanoTime()): TransferSpeedReading {
        val safeTotal = totalBytes.coerceAtLeast(0L)
        val transferred = transferredBytes.coerceIn(0L, safeTotal)
        samples.addLast(nowNanos to transferred)
        while (samples.size > 2 && nowNanos - samples.first().first > windowNanos) {
            samples.removeFirst()
        }
        if (samples.size < 2) return TransferSpeedReading(0L, null)
        val first = samples.first()
        val last = samples.last()
        val elapsed = (last.first - first.first).coerceAtLeast(1L)
        val speed = ((last.second - first.second).coerceAtLeast(0L) * 1_000_000_000L) / elapsed
        val remaining = (safeTotal - last.second).coerceAtLeast(0L)
        return TransferSpeedReading(
            bytesPerSecond = speed,
            etaSeconds = if (speed > 0L) remaining / speed else null,
        )
    }
}
