// The demo popup. It sends the value to the background one time, when you
// add it, and then clears the field. After that it only sees handles.
const send = (type, extra = {}) => browser.runtime.sendMessage({ type, ...extra });
const $ = (id) => document.getElementById(id);
const item = (text) => Object.assign(document.createElement("li"), { textContent: text });

// Show an answer and count it in data-runs, so a repeated answer is still new.
function answer(output, text) {
  output.textContent = text;
  output.dataset.runs = String(Number(output.dataset.runs ?? 0) + 1);
}
const shown = (result) => (typeof result === "string" ? result : `${result.error}: ${result.message}`);

async function render() {
  const state = await send("state");
  $("secrets").replaceChildren(
    ...state.secrets.map((secret) => {
      const li = item(`${secret.handle} for ${secret.domains.join(", ")} `);
      li.dataset.handle = secret.handle;
      const remove = Object.assign(document.createElement("button"), { textContent: "Remove" });
      remove.addEventListener("click", () => send("remove", { handle: secret.handle }).then(render));
      li.append(remove);
      return li;
    }),
  );
  $("events").replaceChildren(...state.events.map((e) => item(`${e.type} ${e.kind} ${e.handle}${e.host ? ` to ${e.host}` : ""}`)));
}

$("add").addEventListener("click", async () => {
  const result = await send("add", {
    handle: $("handle").value,
    value: $("value").value,
    hosts: $("hosts").value,
    header: $("header").value,
    format: $("format").value,
    allowHttp: $("allow-http").checked,
  });
  $("value").value = "";
  await render();
  answer($("add-result"), shown(result));
});

// The popup calls the API itself. Firefox adds the header on the way out,
// so this page never holds the key.
$("call").addEventListener("click", async () => {
  let text;
  try {
    const response = await fetch($("url").value);
    text = JSON.stringify(await response.json());
  } catch (error) {
    text = JSON.stringify({ error: String(error) });
  }
  await render();
  answer($("call-result"), text);
});

$("redact").addEventListener("click", async () => {
  const result = await send("redact", { text: $("prompt").value });
  answer($("redacted"), shown(result));
});

render().then(() => (document.body.dataset.ready = "1"));
