(function () {
  try {
    var pref = localStorage.getItem('vault-theme') || 'system'
    var dark = pref === 'dark' || (pref === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
    if (dark) document.documentElement.classList.add('dark')
  } catch {}
})()
