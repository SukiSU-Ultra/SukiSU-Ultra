<script setup>
import { onBeforeUnmount, onMounted, ref, computed } from 'vue'

const showBackTop = ref(false) // 初始状态设为false
const scrollProgress = ref(0)

// 圆形进度条计算
const radius = 42
const circumference = computed(() => 2 * Math.PI * radius)

function scrollToTop() {
  window.scrollTo({
    top: 0,
    behavior: 'smooth',
  })
}

// 使用更高效的节流函数
function throttle(fn, delay = 50) {
  let timer = null
  return function (...args) {
    if (!timer) {
      timer = setTimeout(() => {
        fn.apply(this, args)
        timer = null
      }, delay)
    }
  }
}

const updateScrollProgress = () => {
  const { scrollY, innerHeight } = window
  const { scrollHeight } = document.documentElement
  const totalScroll = scrollHeight - innerHeight
  scrollProgress.value = totalScroll > 0 ? Math.min(scrollY / totalScroll, 1) : 0
}

const handleScroll = throttle(() => {
  // 当滚动超过100px时显示，否则隐藏
  const shouldShow = window.scrollY > 100
  showBackTop.value = shouldShow
  updateScrollProgress()
})

onMounted(() => {
  window.addEventListener('scroll', handleScroll)
  updateScrollProgress()
})

onBeforeUnmount(() => {
  window.removeEventListener('scroll', handleScroll)
})
</script>

<template>
  <Transition name="fade">
    <div class="back-top-container" v-show="showBackTop">
      <svg class="progress-ring" viewBox="0 0 100 100">
        <circle class="progress-ring-background" cx="50" cy="50" r="42" />
        <circle
          class="progress-ring-circle"
          cx="50"
          cy="50"
          r="42"
          :style="{ 'stroke-dashoffset': circumference - scrollProgress * circumference }"
        />
      </svg>
      <div class="vitepress-backTop-main" title="返回顶部" @click="scrollToTop()">
        <svg class="icon" viewBox="0 0 1024 1024">
          <path
            d="M752.736 431.063C757.159 140.575 520.41 8.97 504.518 0.41V0l-0.45 0.205-0.41-0.205v0.41c-15.934 8.56-252.723 140.165-248.259 430.653-48.21 31.457-98.713 87.368-90.685 184.074 8.028 96.666 101.007 160.768 136.601 157.287 35.595-3.482 25.232-30.31 25.232-30.31l12.206-50.095s52.47 80.569 69.304 80.528c15.114-1.23 87-0.123 95.6 0h0.82c8.602-0.123 80.486-1.23 95.6 0 16.794 0 69.305-80.528 69.305-80.528l12.165 50.094s-10.322 26.83 25.272 30.31c35.595 3.482 128.574-60.62 136.602-157.286 8.028-96.665-42.475-152.617-90.685-184.074z m-248.669-4.26c-6.758-0.123-94.781-3.359-102.891-107.192 2.95-98.714 95.97-107.438 102.891-107.93 6.964 0.492 99.943 9.216 102.892 107.93-8.11 103.833-96.174 107.07-102.892 107.192z m-52.019 500.531c0 11.838-9.42 21.382-21.012 21.382a21.217 21.217 0 0 1-21.054-21.34V821.74c0-11.797 9.421-21.382 21.054-21.382 11.591 0 21.012 9.585 21.012 21.382v105.635z m77.333 57.222a21.504 21.504 0 0 1-21.34 21.626 21.504 21.504 0 0 1-21.34-21.626V827.474c0-11.96 9.543-21.668 21.299-21.668 11.796 0 21.38 9.708 21.38 21.668v157.082z m71.147-82.043c0 11.796-9.42 21.34-21.053 21.34a21.217 21.217 0 0 1-21.013-21.34v-75.367c0-11.755 9.421-21.299 21.013-21.299 11.632 0 21.053 9.544 21.053 21.3v75.366z"
            fill="#FFF"
          />
        </svg>
      </div>
    </div>
  </Transition>
</template>

<style scoped>
.back-top-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  width: 60px;
  height: 60px;
  z-index: 999;
}

.vitepress-backTop-main {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  cursor: pointer;
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background-color: #3eaf7c;
  padding: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2;
  transition: background-color 0.2s ease;
}

.vitepress-backTop-main:hover {
  background-color: #71cda3;
}

.progress-ring {
  position: absolute;
  width: 100%;
  height: 100%;
  transform: rotate(-90deg);
  z-index: 1;
}

.progress-ring-background {
  fill: none;
  stroke: rgba(62, 175, 124, 0.15);
  stroke-width: 3;
}

.progress-ring-circle {
  fill: none;
  stroke: #3eaf7c;
  stroke-width: 3;
  stroke-dasharray: 264; /* 2 * π * 42 */
  stroke-linecap: round;
  transition: stroke-dashoffset 0.15s ease-out;
}

.icon {
  width: 24px;
  height: 24px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
