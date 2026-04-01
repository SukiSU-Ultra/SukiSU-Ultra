<script setup lang="ts">
import confetti from 'canvas-confetti'

const media = window.matchMedia('(prefers-reduced-motion: reduce)')
if (!media.matches) {
  confetti({
    particleCount: 100,
    spread: 170,
    origin: { y: 0.6 },
  })
}
</script>
