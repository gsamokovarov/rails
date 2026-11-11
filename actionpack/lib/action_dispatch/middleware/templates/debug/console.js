{
  const { url } = document.currentScript.dataset

  const host = document.createElement("div")
  const root = host.attachShadow({ mode: "open" })
  const sheet = new CSSStyleSheet()

  sheet.replaceSync(`
    :host {
      all: initial;
      position: fixed;
      inset: auto 0 0 0;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      height: 148px;
      min-height: 40px;
      max-height: 100vh;
      background: #333;
      color: #fff;
      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .resizer { flex: none; height: 4px; cursor: ns-resize; touch-action: none; }
    .log { flex: 1; overflow: auto; padding: 0 6px 4px; }

    pre { margin: 0; font: inherit; white-space: pre-wrap; overflow-wrap: anywhere; }
    .output { color: #1ad027; }
    .error { color: #fc9; }
    .notice { color: #99f; }

    label { display: flex; gap: 1ch; }
    input { flex: 1; padding: 0; border: 0; outline: 0; background: none; color: inherit; font: inherit; }

    button {
      position: absolute;
      top: 4px;
      right: 16px;
      width: 16px;
      height: 16px;
      padding: 0;
      border: 0;
      border-radius: 2px;
      background: none;
      color: #ccc;
      font: inherit;
      line-height: 16px;
      cursor: pointer;
    }
    button:hover { background: #966; color: #fff; }
  `)
  root.adoptedStyleSheets = [sheet]

  const element = (tag, properties = {}, ...children) => {
    const node = Object.assign(document.createElement(tag), properties)
    node.append(...children)
    return node
  }

  const input = element("input", { spellcheck: false, autocapitalize: "off", autocomplete: "off" })
  const prompt = element("label", {}, ">>", input)
  const log = element("div", { className: "log" }, prompt)
  const resizer = element("div", { className: "resizer" })
  const close = element("button", { title: "Close", textContent: "\u00d7" })

  root.append(resizer, close, log)
  document.body.append(host)

  const write = (className, textContent) => {
    prompt.before(element("pre", { className, textContent }))
    log.scrollTop = log.scrollHeight
  }

  let frame = {}

  for (const link of document.querySelectorAll(".trace-frames")) {
    link.addEventListener("click", () => {
      frame = { exception: link.dataset.exceptionObjectId, frame: link.dataset.frameId }
      write("notice", `Context has changed to: ${link.textContent.trim()}`)
    })
  }

  const post = async (params) => {
    try {
      const response = await fetch(url, { method: "POST", body: new URLSearchParams({ ...params, ...frame }) })
      return await response.json()
    } catch {
      return { error: "Failed to reach the server. Make sure it is still running." }
    }
  }

  const storageKey = "rails-debug-console-history"
  const history = JSON.parse(localStorage.getItem(storageKey) ?? "[]")
  let position = history.length

  const execute = async () => {
    const code = input.value
    input.value = ""
    write("echo", `>> ${code}`)

    if (code.trim()) {
      position = history.push(code)
      localStorage.setItem(storageKey, JSON.stringify(history.slice(-100)))
    }

    const { output, error } = await post({ input: code })
    write(error ? "error" : "output", error ?? output)
  }

  const navigate = (offset) => {
    position = Math.min(Math.max(position + offset, 0), history.length)
    input.value = history[position] ?? ""
  }

  const complete = async () => {
    const head = input.value.slice(0, input.selectionStart)
    const [word] = head.match(/[\w@$:.?!]*$/)
    if (!word) return

    const { candidates = [] } = await post({ complete: word })
    if (!candidates.length) return

    let common = candidates[0]
    for (const candidate of candidates) {
      while (!candidate.startsWith(common)) common = common.slice(0, -1)
    }
    input.setRangeText(common, head.length - word.length, head.length, "end")

    if (candidates.length > 1) write("notice", candidates.join("  "))
  }

  input.addEventListener("keydown", (event) => {
    const action = {
      Enter: execute,
      Tab: complete,
      ArrowUp: () => navigate(-1),
      ArrowDown: () => navigate(1),
    }[event.key]

    if (action && !event.isComposing) {
      event.preventDefault()
      action()
    }
  })

  log.addEventListener("click", (event) => {
    if (!event.target.closest("pre")) input.focus()
  })

  resizer.addEventListener("pointerdown", (event) => {
    resizer.setPointerCapture(event.pointerId)
    resizer.onpointermove = ({ clientY }) => host.style.height = `${innerHeight - clientY}px`
    resizer.onpointerup = () => resizer.onpointermove = null
  })

  const observer = new ResizeObserver(() => document.body.style.marginBottom = `${host.offsetHeight}px`)
  observer.observe(host)

  close.addEventListener("click", () => {
    observer.disconnect()
    document.body.style.marginBottom = ""
    host.remove()
  })
}
